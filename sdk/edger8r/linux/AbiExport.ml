(*
 * Copyright (C) 2026 islands-sgx contributors.
 * SPDX-License-Identifier: BSD-3-Clause
 *)

let schema = "atfield-edl-abi-v1"
let tool_fork = "islands-sgx/intel-confidentialComputing_sgx"

let json_string value =
  let buffer = Buffer.create (String.length value + 2) in
  Buffer.add_char buffer '"';
  String.iter (function
    | '"' -> Buffer.add_string buffer "\\\""
    | '\\' -> Buffer.add_string buffer "\\\\"
    | '\b' -> Buffer.add_string buffer "\\b"
    | '\012' -> Buffer.add_string buffer "\\f"
    | '\n' -> Buffer.add_string buffer "\\n"
    | '\r' -> Buffer.add_string buffer "\\r"
    | '\t' -> Buffer.add_string buffer "\\t"
    | ch when Char.code ch < 0x20 ->
        Buffer.add_string buffer (Printf.sprintf "\\u%04x" (Char.code ch))
    | ch -> Buffer.add_char buffer ch
  ) value;
  Buffer.add_char buffer '"';
  Buffer.contents buffer

let json_object fields =
  "{" ^ String.concat "," (List.map
    (fun (key, value) -> json_string key ^ ":" ^ value) fields) ^ "}"

let json_array values = "[" ^ String.concat "," values ^ "]"
let json_bool value = if value then "true" else "false"
let json_int value = string_of_int value

let json_option encode = function
  | None -> "null"
  | Some value -> encode value

let attr_value_json = function
  | Ast.ANumber value ->
      json_object ["kind", json_string "integer"; "value", json_int value]
  | Ast.AString name ->
      json_object ["kind", json_string "identifier"; "name", json_string name]

let signedness_json = function
  | Ast.Signed -> json_string "signed"
  | Ast.Unsigned -> json_string "unsigned"

let builtin_json name fields =
  json_object (["kind", json_string "builtin"; "name", json_string name] @ fields)

let rec type_json = function
  | Ast.Char signedness ->
      builtin_json "char" ["signedness", signedness_json signedness]
  | Ast.Long signedness ->
      builtin_json "long" ["signedness", signedness_json signedness]
  | Ast.LLong signedness ->
      builtin_json "long long" ["signedness", signedness_json signedness]
  | Ast.Int attrs ->
      let modifier = match attrs.Ast.ia_shortness with
        | Ast.IShort -> "short"
        | Ast.ILong -> "long"
        | Ast.INone -> "none"
      in
      builtin_json "int"
        ["signedness", signedness_json attrs.Ast.ia_signedness;
         "modifier", json_string modifier]
  | Ast.Float -> builtin_json "float" []
  | Ast.Double -> builtin_json "double" []
  | Ast.LDouble -> builtin_json "long double" []
  | Ast.Int8 -> builtin_json "int8_t" []
  | Ast.Int16 -> builtin_json "int16_t" []
  | Ast.Int32 -> builtin_json "int32_t" []
  | Ast.Int64 -> builtin_json "int64_t" []
  | Ast.UInt8 -> builtin_json "uint8_t" []
  | Ast.UInt16 -> builtin_json "uint16_t" []
  | Ast.UInt32 -> builtin_json "uint32_t" []
  | Ast.UInt64 -> builtin_json "uint64_t" []
  | Ast.Void -> builtin_json "void" []
  | Ast.WChar -> builtin_json "wchar_t" []
  | Ast.SizeT -> builtin_json "size_t" []
  | Ast.Struct name ->
      json_object ["kind", json_string "struct"; "name", json_string name]
  | Ast.Union name ->
      json_object ["kind", json_string "union"; "name", json_string name]
  | Ast.Enum name ->
      json_object ["kind", json_string "enum"; "name", json_string name]
  | Ast.Foreign name ->
      json_object ["kind", json_string "named"; "name", json_string name]
  | Ast.Ptr target ->
      json_object ["kind", json_string "pointer"; "to", type_json target]

let direction_json = function
  | Ast.PtrIn -> "in"
  | Ast.PtrOut -> "out"
  | Ast.PtrInOut -> "inout"
  | Ast.PtrNoDirection -> "unspecified"

let pointer_attributes_json attrs =
  json_object [
    "size", json_option attr_value_json attrs.Ast.pa_size.Ast.ps_size;
    "count", json_option attr_value_json attrs.Ast.pa_size.Ast.ps_count;
    "string", json_bool attrs.Ast.pa_isstr;
    "wstring", json_bool attrs.Ast.pa_iswstr;
    "user_check", json_bool (not attrs.Ast.pa_chkptr);
    "isptr", json_bool attrs.Ast.pa_isptr;
    "isary", json_bool attrs.Ast.pa_isary;
    "readonly", json_bool attrs.Ast.pa_rdonly
  ]

let rec pointer_depth = function
  | Ast.Ptr target -> 1 + pointer_depth target
  | _ -> 0

(* PTPtr is the EDL pass-by-address marker; pointer_depth counts Ast.Ptr nodes only. *)
let parameter_fields ?(function_parameter=false) ((parameter_type, declarator): Ast.pdecl) =
  let passing, direction, base_type, attributes =
    match parameter_type with
    | Ast.PTVal ty -> "value", "value", ty, "null"
    | Ast.PTPtr (ty, attrs) ->
        "pointer", direction_json attrs.Ast.pa_direction, ty,
        pointer_attributes_json attrs
  in
  [
    "name", json_string declarator.Ast.identifier;
    "type", type_json base_type;
    "parameter_form", json_string passing;
    "pointer_depth", json_int (pointer_depth base_type);
    "direction", json_string direction;
    "array_dimensions", json_array (List.map json_int declarator.Ast.array_dims);
    "array_parameter_decays_to_pointer",
      json_bool (function_parameter && Ast.is_array declarator);
    "attributes", attributes
  ]

let parameter_json parameter =
  json_object (parameter_fields ~function_parameter:true parameter)

let function_parameters function_decl =
  json_array (List.map parameter_json function_decl.Ast.plist)

let ecall_json ordinal (trusted: Ast.trusted_func) =
  let function_decl = trusted.Ast.tf_fdecl in
  json_object [
    "ordinal", json_int ordinal;
    "name", json_string function_decl.Ast.fname;
    "entry_symbol", json_string ("sgx_" ^ function_decl.Ast.fname);
    "visibility", json_string
      (if trusted.Ast.tf_is_priv then "private" else "public");
    "switchless", json_bool trusted.Ast.tf_is_switchless;
    "return_type", type_json function_decl.Ast.rtype;
    "parameters", function_parameters function_decl
  ]

let call_convention_json = function
  | Ast.CC_CDECL -> "cdecl"
  | Ast.CC_STDCALL -> "stdcall"
  | Ast.CC_FASTCALL -> "fastcall"
  | Ast.CC_NONE -> "none"

let ocall_json enclave_name ordinal (untrusted: Ast.untrusted_func) =
  let function_decl = untrusted.Ast.uf_fdecl in
  json_object [
    "ordinal", json_int ordinal;
    "name", json_string function_decl.Ast.fname;
    "entry_symbol",
      json_string (enclave_name ^ "_" ^ function_decl.Ast.fname);
    "switchless", json_bool untrusted.Ast.uf_is_switchless;
    "propagate_errno", json_bool untrusted.Ast.uf_propagate_errno;
    "calling_convention",
      json_string (call_convention_json untrusted.Ast.uf_fattr.Ast.fa_convention);
    "dllimport", json_bool untrusted.Ast.uf_fattr.Ast.fa_dllimport;
    "return_type", type_json function_decl.Ast.rtype;
    "parameters", function_parameters function_decl
  ]

let type_reference_key (kind, name) = kind ^ "\000" ^ name

let type_references ty =
  let rec collect = function
    | Ast.Ptr target -> collect target
    | Ast.Struct name -> ["struct", name]
    | Ast.Union name -> ["union", name]
    | Ast.Enum name -> ["enum", name]
    | Ast.Foreign name -> ["named", name]
    | _ -> []
  in
  collect ty

let parameter_type_references ((parameter_type, _): Ast.pdecl) =
  let ty = match parameter_type with
    | Ast.PTVal ty | Ast.PTPtr (ty, _) -> ty
  in
  type_references ty

let function_type_references function_decl =
  type_references function_decl.Ast.rtype @
  List.flatten (List.map parameter_type_references function_decl.Ast.plist)

let fields_type_references fields =
  List.flatten (List.map (fun (ty, _) -> type_references ty) fields)

let composite_type_references = function
  | Ast.StructDef struct_def ->
      List.flatten (List.map parameter_type_references struct_def.Ast.smlist)
  | Ast.UnionDef union_def -> fields_type_references union_def.Ast.umlist
  | Ast.EnumDef _ -> []

let enum_value_json = function
  | Ast.EnumValNone -> "null"
  | Ast.EnumVal value -> attr_value_json value

let struct_definition_json struct_def =
  let fields =
    List.map (fun member -> json_object (parameter_fields member))
      struct_def.Ast.smlist
  in
  json_object [
    "kind", json_string "struct";
    "name", json_string struct_def.Ast.sname;
    "fields", json_array fields
  ]

let union_definition_json union_def =
  let fields = List.map (fun (ty, declarator) ->
    json_object [
      "name", json_string declarator.Ast.identifier;
      "type", type_json ty;
      "pointer_depth", json_int (pointer_depth ty);
      "array_dimensions",
        json_array (List.map json_int declarator.Ast.array_dims)
    ]) union_def.Ast.umlist
  in
  json_object [
    "kind", json_string "union";
    "name", json_string union_def.Ast.uname;
    "fields", json_array fields
  ]

let enum_definition_json enum_def =
  let values = List.map (fun (name, value) ->
    json_object ["name", json_string name; "value", enum_value_json value])
    enum_def.Ast.enbody
  in
  json_object [
    "kind", json_string "enum";
    "name", json_option json_string
      (if enum_def.Ast.enname = "" then None else Some enum_def.Ast.enname);
    "values", json_array values
  ]

let composite_definition_json = function
  | Ast.StructDef struct_def -> struct_definition_json struct_def
  | Ast.UnionDef union_def -> union_definition_json union_def
  | Ast.EnumDef enum_def -> enum_definition_json enum_def

let composite_key = function
  | Ast.StructDef struct_def -> "struct", struct_def.Ast.sname
  | Ast.UnionDef union_def -> "union", union_def.Ast.uname
  | Ast.EnumDef enum_def -> "enum", enum_def.Ast.enname

let type_definitions enclave =
  let definitions = List.map composite_definition_json enclave.Ast.comp_defs in
  let defined_keys =
    List.map (fun composite -> type_reference_key (composite_key composite))
      enclave.Ast.comp_defs
  in
  let references =
    List.flatten (List.map composite_type_references enclave.Ast.comp_defs) @
    List.flatten (List.map (fun tf ->
      function_type_references tf.Ast.tf_fdecl) enclave.Ast.tfunc_decls) @
    List.flatten (List.map (fun uf ->
      function_type_references uf.Ast.uf_fdecl) enclave.Ast.ufunc_decls)
  in
  let unresolved =
    List.fold_left (fun acc reference ->
      let key = type_reference_key reference in
      if List.mem key defined_keys ||
         List.exists (fun existing -> type_reference_key existing = key) acc
      then acc
      else acc @ [reference]
    ) [] references
  in
  definitions @ List.map (fun (kind, name) ->
    json_object [
      "kind", json_string kind;
      "name", json_string name;
      "resolved", json_bool false
    ]) unresolved

let ordinals length =
  let rec collect current =
    if current >= length then [] else current :: collect (current + 1)
  in
  collect 0

let ocall_allow_matrix enclave =
  let ocall_ordinals = ordinals (List.length enclave.Ast.ufunc_decls) in
  let ecall_ordinals = ordinals (List.length enclave.Ast.tfunc_decls) in
  let values = List.map (fun untrusted ->
    json_array (List.map (fun trusted ->
      json_bool (List.mem
        trusted.Ast.tf_fdecl.Ast.fname untrusted.Ast.uf_allow_list))
      enclave.Ast.tfunc_decls))
    enclave.Ast.ufunc_decls
  in
  json_object [
    "ocall_ordinals", json_array (List.map json_int ocall_ordinals);
    "ecall_ordinals", json_array (List.map json_int ecall_ordinals);
    "values", json_array values
  ]

let to_json (enclave: Ast.enclave_content) input =
  json_object [
    "schema", json_string schema;
    "input", json_object [
      "root", json_string (Filename.basename input);
      "imports", json_array
        (List.map json_string enclave.Ast.import_sources)
    ];
    "tool", json_object [
      "name", json_string "sgx_edger8r";
      "fork", json_string tool_fork
    ];
    "types", json_array (type_definitions enclave);
    "ecalls", json_array (List.mapi ecall_json enclave.Ast.tfunc_decls);
    "ocalls", json_array (List.mapi
      (ocall_json enclave.Ast.enclave_name) enclave.Ast.ufunc_decls);
    "ocall_allow_matrix", ocall_allow_matrix enclave
  ]
