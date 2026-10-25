/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef ISLANDS_SGX_SIGNER_LAYOUT_H
#define ISLANDS_SGX_SIGNER_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ISLANDS_SGX_SIGNER_LAYOUT_MAX_RECORDS 1024u

/* Byte-for-byte representation of one SGX DIR_LAYOUT record. */
typedef struct islands_sgx_signer_layout_record {
    uint16_t id;
    uint16_t second;
    uint32_t u32;
    uint64_t u64;
    uint32_t words[4];
} islands_sgx_signer_layout_record;

typedef struct islands_sgx_signer_static_tcs {
    uint64_t instance;
    uint64_t tcs_rva;
    uint64_t stack_bottom;
    uint64_t stack_page_count;
    uint64_t stack_top;
    uint64_t td_bottom;
    uint64_t td_page_count;
    uint64_t td_top;
    uint64_t fs_base_rva;
    uint64_t gs_base_rva;
} islands_sgx_signer_static_tcs;

typedef struct islands_sgx_signer_layout_result_v3 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t metadata_version;
    uint64_t enclave_size;
    uint64_t ordinary_image_end_rva;
    uint32_t layout_count;
    islands_sgx_signer_layout_record records[ISLANDS_SGX_SIGNER_LAYOUT_MAX_RECORDS];
    uint32_t static_tcs_capacity;
    uint32_t static_tcs_count;
    islands_sgx_signer_static_tcs *static_tcs;
} islands_sgx_signer_layout_result_v3;

#define ISLANDS_SGX_SIGNER_LAYOUT_ABI_V3 3u

/* Build metadata/layout only; no loading, hashing, signing, or file update. */
int islands_sgx_build_signer_layout_v3(
    const uint8_t *elf, size_t elf_size, const char *config_path,
    islands_sgx_signer_layout_result_v3 *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif
