/* SPDX-License-Identifier: BSD-3-Clause */

#include "islands_sgx_signer_layout.h"
#include "elf_helper.h"
#include "manage_metadata.h"
#include "metadata.h"
#include "parserfactory.h"
#include "sgx_error.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

static_assert(sizeof(islands_sgx_signer_layout_record) == sizeof(layout_t),
              "layout record ABI must match SGX DIR_LAYOUT");
static_assert(sizeof(islands_sgx_signer_layout_record) == 32,
              "layout record ABI must be exactly 32 bytes");
static_assert(offsetof(islands_sgx_signer_layout_record, id) == offsetof(layout_entry_t, id), "id offset");
static_assert(offsetof(islands_sgx_signer_layout_record, second) == offsetof(layout_entry_t, attributes), "second offset");
static_assert(offsetof(islands_sgx_signer_layout_record, u32) == offsetof(layout_entry_t, page_count), "u32 offset");
static_assert(offsetof(islands_sgx_signer_layout_record, u64) == offsetof(layout_entry_t, rva), "u64 offset");
static_assert(offsetof(islands_sgx_signer_layout_record, words) == offsetof(layout_entry_t, content_size), "words offset");
static_assert(offsetof(islands_sgx_signer_layout_result_v3, records) == 40, "result alignment");
static_assert(PARAMETER_COUNT == 37, "XML parameter table changed unexpectedly");

static int build_signer_layout_impl(
    const uint8_t *elf, size_t elf_size, const char *config_path,
    islands_sgx_signer_layout_result_v3 *out,
    std::vector<islands_sgx_signer_static_tcs> *typed_result)
{
    if (elf == NULL || elf_size == 0 || config_path == NULL || out == NULL)
        return 1;

    xml_parameter_t parameter[PARAMETER_COUNT];
    if (!initialize_xml_parameters(parameter, PARAMETER_COUNT) ||
        !parse_metadata_file(config_path, parameter, PARAMETER_COUNT) ||
        parameter[TCSNUM].flag == 0 ||
        parameter[TCSNUM].value == 0 ||
        parameter[TCSPOLICY].flag == 0 ||
        parameter[TCSPOLICY].value != TCS_POLICY_BIND ||
        parameter[ENABLEAEXNOTIFY].flag == 0 ||
        parameter[ENABLEAEXNOTIFY].value != 1 ||
        parameter[ENABLEOSSLFIPS].value != 0)
        return 1;

    std::unique_ptr<BinParser> parser(
        binparser::get_parser(const_cast<uint8_t *>(elf), elf_size));
    if (!parser || parser->run_parser() != SGX_SUCCESS)
        return 1;
    if (parser->has_init_section())
        return 1;

    const metadata_t *existing = reinterpret_cast<const metadata_t *>(
        parser->get_start_addr() + parser->get_metadata_offset());
    if (existing->magic_num == METADATA_MAGIC)
        return 1;

    const bool no_text_relocations =
        parser->get_bin_format() == BF_ELF64
            ? ElfHelper<64>::dump_textrels(parser.get())
            : ElfHelper<32>::dump_textrels(parser.get());
    if (!no_text_relocations)
        return 1;

    metadata_t metadata;
    std::memset(&metadata, 0, sizeof(metadata));
    std::vector<islands_sgx_signer_static_tcs> typed;
    uint8_t meta_versions = 0;
    if (!build_metadata_core(&metadata, parser.get(), NULL, parameter, out,
                             &meta_versions, &typed) ||
        !finalize_metadata_core(&metadata, parameter, meta_versions) ||
        !refresh_signer_layout_result(&metadata, out))
        return 1;
    if (typed_result != NULL)
        *typed_result = std::move(typed);
    return 0;
}

extern "C" int islands_sgx_build_signer_layout_v3(
    const uint8_t *elf, size_t elf_size, const char *config_path,
    islands_sgx_signer_layout_result_v3 *out, size_t out_size)
{
    if (out == NULL || out_size < sizeof(*out) ||
        out->abi_version != ISLANDS_SGX_SIGNER_LAYOUT_ABI_V3 ||
        out->struct_size != sizeof(*out) ||
        (out->static_tcs_capacity != 0 && out->static_tcs == NULL))
        return 1;
    const uint32_t static_tcs_capacity = out->static_tcs_capacity;
    islands_sgx_signer_static_tcs *static_tcs = out->static_tcs;

    std::vector<islands_sgx_signer_static_tcs> typed;
    if (build_signer_layout_impl(elf, elf_size, config_path, out, &typed) !=
            0 ||
        out->abi_version != ISLANDS_SGX_SIGNER_LAYOUT_ABI_V3 ||
        out->struct_size != sizeof(*out) ||
        out->static_tcs_capacity != static_tcs_capacity ||
        out->static_tcs != static_tcs ||
        typed.size() > static_tcs_capacity)
        return 1;

    if (!typed.empty())
        std::memcpy(out->static_tcs, typed.data(),
                    typed.size() * sizeof(out->static_tcs[0]));
    out->static_tcs_count = static_cast<uint32_t>(typed.size());
    return 0;
}
