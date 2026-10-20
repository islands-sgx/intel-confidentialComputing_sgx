import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const testFile = fileURLToPath(import.meta.url);
const testsDir = dirname(testFile);
const linuxDir = resolve(testsDir, "..");
const fixtureDir = resolve(testsDir, "abi");
const rootEld = resolve(fixtureDir, "root.edl");
const binary = resolve(linuxDir, "_build/Edger8r.native");
const goldenPath = resolve(fixtureDir, "root.expected.json");

type TableRow = {
  entrySymbol: string;
  isPrivate?: boolean;
  isSwitchless?: boolean;
};

function run(args: string[]) {
  const result = spawnSync(binary, args, { cwd: linuxDir, encoding: "utf8" });
  if (result.error) throw result.error;
  return result;
}

function requireMatch(source: string, expression: RegExp, description: string) {
  const match = source.match(expression);
  if (!match) throw new Error("Could not parse generated " + description);
  return match;
}

function parseEcallTable(source: string): { count: number; rows: TableRow[] } {
  const match = requireMatch(
    source,
    /}\s*g_ecall_table\s*=\s*\{\s*(\d+)\s*,\s*\{([\s\S]*?)\}\s*\}\s*;/,
    "ECALL table"
  );
  const rows = [...match[2].matchAll(
    /\{\s*\(void\*\)\(uintptr_t\)\s*([A-Za-z_]\w*)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}/g
  )].map((row) => ({
    entrySymbol: row[1],
    isPrivate: row[2] === "1",
    isSwitchless: row[3] === "1",
  }));
  return { count: Number(match[1]), rows };
}

function parseOcallTable(source: string): { count: number; symbols: string[] } {
  const match = requireMatch(
    source,
    /}\s*ocall_table_[A-Za-z_]\w*\s*=\s*\{\s*(\d+)\s*,\s*\{([\s\S]*?)\}\s*\}\s*;/,
    "OCALL table"
  );
  const symbols = [...match[2].matchAll(/\(void\*\)\s*([A-Za-z_]\w*)/g)]
    .map((row) => row[1]);
  return { count: Number(match[1]), symbols };
}

function parseEntryMatrix(source: string) {
  const dimension = requireMatch(
    source,
    /uint8_t\s+entry_table\[(\d+)\]\[(\d+)\]\s*;/,
    "dynamic entry table dimensions"
  );
  const initializer = requireMatch(
    source,
    /g_dyn_entry_table\s*=\s*\{\s*\d+\s*,\s*\{([\s\S]*?)\}\s*\}\s*;/,
    "dynamic entry table initializer"
  );
  const rows = [...initializer[1].matchAll(/\{([^{}]*)\}/g)].map((match) =>
    match[1].split(",").map((cell) => cell.trim()).filter(Boolean).map((cell) => {
      const value = Number(cell);
      if (value !== 0 && value !== 1) throw new Error("Invalid entry bit: " + cell);
      return value === 1;
    })
  );
  return {
    rowCount: Number(dimension[1]),
    columnCount: Number(dimension[2]),
    values: rows,
  };
}

function parseEcallCalls(source: string) {
  return [...source.matchAll(
    /\bsgx_ecall(_switchless)?\(\s*eid\s*,\s*(\d+)\s*,/g
  )].map((match) => ({
    ordinal: Number(match[2]),
    switchless: match[1] === "_switchless",
  }));
}

function parseOcallCalls(source: string) {
  return [...source.matchAll(
    /\bsgx_ocall(_switchless)?\(\s*(\d+)\s*,/g
  )].map((match) => ({
    ordinal: Number(match[2]),
    switchless: match[1] === "_switchless",
  }));
}

test("exports the resolved AST ABI and matches generated edge tables", () => {
  const dump = run(["--search-path", fixtureDir, "--dump-abi-json", rootEld]);
  if (dump.status !== 0) throw new Error(dump.stderr);
  const abi = JSON.parse(dump.stdout);
  const golden = JSON.parse(readFileSync(goldenPath, "utf8"));
  expect(abi).toEqual(golden);

  expect(abi.schema).toBe("atfield-edl-abi-v1");
  expect(abi.tool).toEqual({
    name: "sgx_edger8r",
    fork: "islands-sgx/intel-confidentialComputing_sgx",
  });
  expect(abi.input.imports).toContain("imports/common.edl");
  expect(abi.input.imports).toContain("imports/other/common.edl");
  expect(abi.input.imports).toContain("imports/nested.edl");
  expect(abi.ecalls.map((entry: any) => entry.ordinal))
    .toEqual(abi.ecalls.map((_: any, index: number) => index));
  expect(abi.ecalls.map((entry: any) => entry.name)).toContain("collision_ecall");

  const parameters = new Map(
    abi.ecalls.flatMap((entry: any) =>
      entry.parameters.map((parameter: any) => [parameter.name, parameter] as const)
    )
  );
  expect(parameters.get("indirect").pointer_depth).toBe(2);
  expect(parameters.get("indirect").type).toEqual({
    kind: "pointer",
    to: { kind: "pointer", to: { kind: "builtin", name: "int32_t" } },
  });
  expect(parameters.get("fixed").pointer_depth).toBe(0);
  expect(parameters.get("fixed").parameter_form).toBe("pointer");
  expect(parameters.get("fixed").array_dimensions).toEqual([3]);
  expect(parameters.get("fixed").array_parameter_decays_to_pointer).toBe(true);
  expect(parameters.get("bytes").attributes.size).toEqual({
    kind: "identifier",
    name: "length",
  });
  expect(parameters.get("fixed_count").attributes.count).toEqual({
    kind: "integer",
    value: 3,
  });
  expect(parameters.get("four_bytes").attributes.size).toEqual({
    kind: "integer",
    value: 4,
  });
  expect(parameters.get("indirect").attributes.size).toEqual({
    kind: "identifier",
    name: "length",
  });
  expect(parameters.get("values").direction).toBe("inout");
  expect(parameters.get("values").attributes.count).toEqual({
    kind: "identifier",
    name: "capacity",
  });
  expect(parameters.get("fixed").direction).toBe("in");
  expect(parameters.get("output").direction).toBe("out");
  expect(parameters.get("text").attributes.string).toBe(true);
  expect(parameters.get("wide").attributes.wstring).toBe(true);
  expect(parameters.get("opaque").attributes.user_check).toBe(true);
  expect(abi.ocall_allow_matrix.ocall_ordinals).toEqual([0]);
  expect(abi.ocall_allow_matrix.ecall_ordinals)
    .toEqual(abi.ecalls.map((entry: any, index: number) => index));
  expect(abi.types).toContainEqual({
    kind: "named",
    name: "Payload",
    resolved: false,
  });

  const tempRoot = mkdtempSync(resolve(tmpdir(), "edger8r-abi-"));
  try {
    const trustedDir = resolve(tempRoot, "trusted");
    const untrustedDir = resolve(tempRoot, "untrusted");
    mkdirSync(trustedDir);
    mkdirSync(untrustedDir);
    const generated = run([
      "--search-path", fixtureDir,
      "--trusted-dir", trustedDir,
      "--untrusted-dir", untrustedDir,
      rootEld,
    ]);
    if (generated.status !== 0) throw new Error(generated.stderr);

    const trusted = readFileSync(resolve(trustedDir, "root_t.c"), "utf8");
    const untrusted = readFileSync(resolve(untrustedDir, "root_u.c"), "utf8");
    const ecallTable = parseEcallTable(trusted);
    expect(ecallTable.count).toBe(abi.ecalls.length);
    expect(ecallTable.rows).toEqual(abi.ecalls.map((entry: any) => ({
      entrySymbol: entry.entry_symbol,
      isPrivate: entry.visibility === "private",
      isSwitchless: entry.switchless,
    })));

    const ocallTable = parseOcallTable(untrusted);
    expect(ocallTable.count).toBe(abi.ocalls.length);
    expect(ocallTable.symbols).toEqual(
      abi.ocalls.map((entry: any) => entry.entry_symbol)
    );

    const entryMatrix = parseEntryMatrix(trusted);
    expect(entryMatrix.rowCount).toBe(abi.ocall_allow_matrix.ocall_ordinals.length);
    expect(entryMatrix.columnCount).toBe(abi.ocall_allow_matrix.ecall_ordinals.length);
    expect(entryMatrix.values).toEqual(abi.ocall_allow_matrix.values);

    expect(parseEcallCalls(untrusted)).toEqual(
      abi.ecalls.map((entry: any) => ({
        ordinal: entry.ordinal,
        switchless: entry.switchless,
      }))
    );
    expect(parseOcallCalls(trusted)).toEqual(
      abi.ocalls.map((entry: any) => ({
        ordinal: entry.ordinal,
        switchless: entry.switchless,
      }))
    );
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("ABI export accepts exactly one input", () => {
  const result = run([
    "--dump-abi-json",
    rootEld,
    rootEld,
  ]);
  expect(result.status).not.toBe(0);
  expect(result.stdout).toBe("");
});
