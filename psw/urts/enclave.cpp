/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "enclave.h"
#include "util.h"
#include "se_detect.h"
#include "enclave_creator.h"
#include "sgx_error.h"
#include "se_error_internal.h"
#include "debugger_support.h"
#include "se_memory.h"
#include "urts_emm.h"
#include "rts_cmd.h"
#include <assert.h>
#include "rts.h"
#include "get_thread_id.h"
#include "sgx_switchless_itf.h"
#include "sgx_enclave_common.h"
#include <algorithm>
#include <climits>
#include <errno.h>
#include <limits>
#include <stdint.h>

int do_ecall(const int fn, const void *ocall_table, const void *ms, CTrustThread *trust_thread);
int do_ocall(const bridge_fn_t bridge, void *ms);

namespace {
struct ReadinessTxnFrame
{
    explicit ReadinessTxnFrame(sgx_enclave_id_t id);
    ~ReadinessTxnFrame();
    sgx_enclave_id_t enclave_id;
    ReadinessTxnFrame *previous;
};

thread_local ReadinessTxnFrame *current_readiness_txn = NULL;
thread_local CEnclave *current_destroy_uninit = NULL;

ReadinessTxnFrame::ReadinessTxnFrame(sgx_enclave_id_t id)
    : enclave_id(id), previous(current_readiness_txn)
{
    current_readiness_txn = this;
}

ReadinessTxnFrame::~ReadinessTxnFrame()
{
    assert(current_readiness_txn == this);
    current_readiness_txn = previous;
}

struct DestroyUninitFrame
{
    explicit DestroyUninitFrame(CEnclave *value)
        : previous(current_destroy_uninit)
    {
        current_destroy_uninit = value;
    }
    ~DestroyUninitFrame()
    {
        current_destroy_uninit = previous;
    }
    CEnclave *previous;
};
}

bool readiness_txn_on_current_thread(sgx_enclave_id_t enclave_id)
{
    for (ReadinessTxnFrame *frame = current_readiness_txn;
         frame != NULL; frame = frame->previous)
    {
        if (frame->enclave_id == enclave_id)
            return true;
    }
    return false;
}

CEnclave::CEnclave()
    : m_enclave_id(0)
    , m_start_addr(NULL)
    , m_size(0)
    , m_power_event_flag(0)
    , m_ref(0)
    , m_zombie(false)
    , m_thread_pool(NULL)
    , m_dbg_flag(false)
    , m_destroyed(false)
    , m_version(0)
    , m_ocall_table(NULL)
    , m_pthread_tid(0)
    , m_pthread_is_valid(false)
    , m_new_thread_event(NULL)
    , m_sealed_key(NULL)
    , m_switchless(NULL)
    , m_first_ecall(true)
    , m_aex_notify(false)
    , m_dynamic_tcs_list_size(0)
    , m_page_readiness_started(false)
    , m_page_readiness_table_set(false)
    , m_page_readiness_backend_set(false)
    , m_page_readiness_backend(PAGE_READINESS_BACKEND_KERNEL)
    , m_page_readiness_table_installed(false)
    , m_page_readiness_broken(false)
    , m_destroying(false)
{
    memset(&m_enclave_info, 0, sizeof(debug_enclave_info_t));
    memset(&m_target_info, 0, sizeof(sgx_target_info_t));
    se_init_rwlock(&m_rwlock);
#ifdef SE_SIM
    m_global_data_sim_ptr = NULL;
#endif

}

// global for all the enclaves in application
sgx_switchless_funcs_t g_sl_funcs = { NULL, NULL, NULL, NULL, NULL };

void sgx_set_switchless_itf(const sgx_switchless_funcs_t* sl_funcs)
{
    g_sl_funcs = *sl_funcs;
}



sgx_status_t CEnclave::init_uswitchless(const void* config)
{
    if(!se_try_rdlock(&m_rwlock)) return SGX_ERROR_ENCLAVE_LOST;

    sgx_status_t status = SGX_ERROR_UNEXPECTED;

    //Maybe the enclave has been destroyed after acquire/release m_rwlock. See CEnclave::destroy()
    if (m_destroyed) {
        status = SGX_ERROR_ENCLAVE_LOST;
        goto on_exit;
    }

    if (g_sl_funcs.sl_init_func_ptr)
    {
        status = g_sl_funcs.sl_init_func_ptr(m_enclave_id, config, &m_switchless);
    }
    else
    {
        status = SGX_ERROR_UNEXPECTED;
        goto on_exit;
    }

on_exit:
    se_rdunlock(&m_rwlock);
    return status;
}


void CEnclave::destroy_uswitchless(void)
{
    if (m_switchless)
    {
        g_sl_funcs.sl_destroy_func_ptr(m_switchless);
    }
}


sgx_status_t CEnclave::initialize(const se_file_t& file,  CLoader &ldr, const uint64_t enclave_size, const uint32_t tcs_policy, const uint32_t enclave_version, const uint32_t tcs_min_pool)
{
    const secs_t& secs = ldr.get_secs();

    try
    {
        m_readable_reg_rvas = ldr.get_readable_reg_pages();
        m_business_reg_rvas = ldr.get_business_reg_pages();
        std::sort(m_readable_reg_rvas.begin(), m_readable_reg_rvas.end());
        m_readable_reg_rvas.erase(
            std::unique(m_readable_reg_rvas.begin(), m_readable_reg_rvas.end()),
            m_readable_reg_rvas.end());
        std::sort(m_business_reg_rvas.begin(), m_business_reg_rvas.end());
        m_business_reg_rvas.erase(
            std::unique(m_business_reg_rvas.begin(), m_business_reg_rvas.end()),
            m_business_reg_rvas.end());
    }
    catch (...)
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    if (file.name != NULL)
    {
        uint32_t name_len = file.name_len;
        if (file.unicode)
            name_len *= (uint32_t)sizeof(wchar_t);

        const int buf_len = name_len + 4; //+4, because we need copy the charactor of string end ('\0').;

        m_enclave_info.lpFileName = calloc(1, buf_len);
        if (m_enclave_info.lpFileName == NULL)
            return SGX_ERROR_OUT_OF_MEMORY;

        memcpy_s(m_enclave_info.lpFileName, name_len, file.name, name_len);
        m_enclave_info.unicode = file.unicode?1:0;
        m_enclave_info.file_name_size = name_len;
    }

    m_enclave_info.struct_version = DEBUG_INFO_STRUCT_VERSION;
    
    m_enclave_id = ldr.get_enclave_id();
    m_start_addr = (void*)ldr.get_start_addr();
    m_size = enclave_size;
    m_version = enclave_version;

    m_new_thread_event = se_event_init();
    if(m_new_thread_event == NULL)
    {
        free(m_enclave_info.lpFileName);
        m_enclave_info.lpFileName = NULL;
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    if(TCS_POLICY_BIND == tcs_policy)
    {
        m_thread_pool = new CThreadPoolBindMode(tcs_min_pool);
    }
    else if(TCS_POLICY_UNBIND == tcs_policy)
    {
        //we also set it as bind mode.
        m_thread_pool = new CThreadPoolUnBindMode(tcs_min_pool);
    }
    else
    {
        SE_TRACE(SE_TRACE_WARNING, "BUG: unknown tcs policy\n");
        //Should NOT run here, because we have validate the metadata before.
        free(m_enclave_info.lpFileName);
        m_enclave_info.lpFileName = NULL;
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    set_dynamic_tcs_list_size(ldr);
#ifdef SE_SIM
    set_global_data_sim_ptr(ldr);
#endif
    
    if (memcpy_s(&m_target_info.mr_enclave, sizeof(sgx_measurement_t), &secs.mr_enclave, sizeof(sgx_measurement_t)))
    {
        free(m_enclave_info.lpFileName);
        m_enclave_info.lpFileName = NULL;
        return SGX_ERROR_UNEXPECTED;
    }
        
    m_target_info.attributes = secs.attributes;
    m_target_info.config_svn = secs.config_svn;
    m_target_info.misc_select = secs.misc_select;
    if (memcpy_s(m_target_info.config_id, sizeof(sgx_config_id_t), secs.config_id, sizeof(sgx_config_id_t)))
    {
        free(m_enclave_info.lpFileName);
        m_enclave_info.lpFileName = NULL;
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

static uint64_t readiness_read_le64(const uint8_t *data)
{
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= ((uint64_t)data[i]) << (i * 8);
    return value;
}

static bool readiness_table_size(uint64_t entry_count, uint64_t page_count, size_t *size_out)
{
    const uint64_t max_size = (uint64_t)std::numeric_limits<size_t>::max();
    if (size_out == NULL || entry_count > (max_size - 32) / 24)
        return false;

    const uint64_t prefix_size = 32 + entry_count * 24;
    if (page_count > (max_size - prefix_size) / 8)
        return false;

    *size_out = (size_t)(prefix_size + page_count * 8);
    return true;
}

static sgx_status_t readiness_errno_to_status(int error)
{
    switch (error)
    {
    case EINVAL:
    case EFAULT:
    case EOVERFLOW:
        return SGX_ERROR_INVALID_PARAMETER;
    case ENOMEM:
        return SGX_ERROR_OUT_OF_MEMORY;
    case EBUSY:
    case EAGAIN:
        return SGX_ERROR_BUSY;
    case ENOENT:
    case EBADF:
    case ENODEV:
        return SGX_ERROR_ENCLAVE_LOST;
    case ENOTTY:
    case ENOSYS:
        return SGX_ERROR_FEATURE_NOT_SUPPORTED;
    default:
        return SGX_ERROR_UNEXPECTED;
    }
}

bool CEnclave::is_readiness_txn_on_current_thread() const
{
    return readiness_txn_on_current_thread(m_enclave_id);
}

bool CEnclave::mark_destroying()
{
    bool expected = false;
    return m_destroying.compare_exchange_strong(expected, true,
                                                std::memory_order_acq_rel);
}

void CEnclave::wait_for_active_calls()
{
    se_wtlock(&m_rwlock);
    se_wtunlock(&m_rwlock);
}

sgx_status_t CEnclave::uninitialize_for_destroy()
{
    DestroyUninitFrame frame(this);
    return ecall(ECMD_UNINIT_ENCLAVE, NULL, NULL);
}

sgx_status_t CEnclave::set_ecall_page_readiness_table(const sgx_page_readiness_table_t *table)
{
    if (table == NULL || table->data == NULL || table->size < 32)
        return SGX_ERROR_INVALID_PARAMETER;
    if (m_page_readiness_started.load(std::memory_order_acquire) ||
        is_readiness_txn_on_current_thread())
        return SGX_ERROR_INVALID_STATE;

    se_wtlock(&m_rwlock);
    if (m_destroyed || m_destroying.load(std::memory_order_acquire) ||
        m_page_readiness_table_set ||
        m_page_readiness_started.load(std::memory_order_acquire) || m_switchless != NULL)
    {
        se_wtunlock(&m_rwlock);
        return SGX_ERROR_INVALID_STATE;
    }

    const uint64_t version = readiness_read_le64(table->data);
    const uint64_t entry_count = readiness_read_le64(table->data + 8);
    const uint64_t page_count = readiness_read_le64(table->data + 16);
    const uint64_t reserved = readiness_read_le64(table->data + 24);
    size_t expected_size = 0;
    if (version != 3 || reserved != 0 ||
        entry_count > (uint64_t)INT_MAX + 1 ||
        !readiness_table_size(entry_count, page_count, &expected_size) ||
        expected_size != table->size ||
        page_count > (uint64_t)(std::numeric_limits<size_t>::max() / sizeof(uint64_t)) ||
        (m_start_addr == NULL || m_size < SE_PAGE_SIZE ||
         m_size > UINTPTR_MAX - (uintptr_t)m_start_addr))
    {
        se_wtunlock(&m_rwlock);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::vector<uint8_t> table_bytes;
    std::vector<ecall_page_readiness_entry_t> entries;
    std::vector<uint64_t> page_rvas;
    try
    {
        table_bytes.assign(table->data, table->data + table->size);
        entries.reserve((size_t)entry_count);
        page_rvas.reserve((size_t)page_count);
    }
    catch (...)
    {
        se_wtunlock(&m_rwlock);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    const uint8_t *bytes = table_bytes.data();
    if (readiness_read_le64(bytes) != version ||
        readiness_read_le64(bytes + 8) != entry_count ||
        readiness_read_le64(bytes + 16) != page_count ||
        readiness_read_le64(bytes + 24) != reserved)
    {
        se_wtunlock(&m_rwlock);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint64_t expected_first_page = 0;
    uint64_t previous_selector = 0;
    for (uint64_t i = 0; i < entry_count; ++i)
    {
        const size_t offset = 32 + (size_t)i * 24;
        ecall_page_readiness_entry_t entry;
        entry.selector = readiness_read_le64(bytes + offset);
        entry.first_page = readiness_read_le64(bytes + offset + 8);
        entry.page_count = readiness_read_le64(bytes + offset + 16);

        if (entry.selector > INT_MAX ||
            (i != 0 && entry.selector <= previous_selector) ||
            entry.first_page != expected_first_page ||
            expected_first_page > page_count ||
            entry.page_count > page_count - expected_first_page)
        {
            se_wtunlock(&m_rwlock);
            return SGX_ERROR_INVALID_PARAMETER;
        }

        const uint64_t first = entry.first_page;
        uint64_t previous_rva = 0;
        for (uint64_t j = 0; j < entry.page_count; ++j)
        {
            const size_t page_offset = 32 + (size_t)entry_count * 24 +
                                       (size_t)(first + j) * 8;
            const uint64_t rva = readiness_read_le64(bytes + page_offset);
            if ((rva & (SE_PAGE_SIZE - 1)) != 0 ||
                rva > m_size - SE_PAGE_SIZE ||
                (j != 0 && rva <= previous_rva) ||
                !std::binary_search(m_business_reg_rvas.begin(), m_business_reg_rvas.end(), rva))
            {
                se_wtunlock(&m_rwlock);
                return SGX_ERROR_INVALID_PARAMETER;
            }
            try
            {
                page_rvas.push_back(rva);
            }
            catch (...)
            {
                se_wtunlock(&m_rwlock);
                return SGX_ERROR_OUT_OF_MEMORY;
            }
            previous_rva = rva;
        }

        expected_first_page += entry.page_count;
        previous_selector = entry.selector;
        try
        {
            entries.push_back(entry);
        }
        catch (...)
        {
            se_wtunlock(&m_rwlock);
            return SGX_ERROR_OUT_OF_MEMORY;
        }
    }

    if (expected_first_page != page_count || page_rvas.size() != (size_t)page_count)
    {
        se_wtunlock(&m_rwlock);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    m_page_readiness_bytes.swap(table_bytes);
    m_page_readiness_entries.swap(entries);
    m_page_readiness_rvas.swap(page_rvas);
    m_page_readiness_table_set = true;
    se_wtunlock(&m_rwlock);
    return SGX_SUCCESS;
}

sgx_status_t CEnclave::set_ecall_page_readiness_backend(uint32_t backend)
{
    if (backend != PAGE_READINESS_BACKEND_KERNEL &&
        backend != PAGE_READINESS_BACKEND_USERSPACE)
        return SGX_ERROR_INVALID_PARAMETER;
    if (m_page_readiness_started.load(std::memory_order_acquire) ||
        is_readiness_txn_on_current_thread())
        return SGX_ERROR_INVALID_STATE;

    se_wtlock(&m_rwlock);
    if (m_destroyed || m_destroying.load(std::memory_order_acquire) ||
        !m_page_readiness_table_set || m_page_readiness_backend_set ||
        m_page_readiness_started.load(std::memory_order_acquire))
    {
        se_wtunlock(&m_rwlock);
        return SGX_ERROR_INVALID_STATE;
    }

    if (backend == PAGE_READINESS_BACKEND_USERSPACE && !m_page_readiness_rvas.empty())
    {
        if (!m_dbg_flag)
        {
            SE_TRACE(SE_TRACE_WARNING,
                     "Islands userspace readiness requires a debug enclave\n");
            se_wtunlock(&m_rwlock);
            return SGX_ERROR_FEATURE_NOT_SUPPORTED;
        }
        for (size_t i = 0; i < m_page_readiness_rvas.size(); ++i)
        {
            if (!std::binary_search(m_readable_reg_rvas.begin(), m_readable_reg_rvas.end(),
                                    m_page_readiness_rvas[i]))
            {
                SE_TRACE(SE_TRACE_WARNING,
                         "Islands userspace readiness target is not signed readable REG RVA=0x%llx\n",
                         (unsigned long long)m_page_readiness_rvas[i]);
                se_wtunlock(&m_rwlock);
                return SGX_ERROR_INVALID_PARAMETER;
            }
        }
    }

    m_page_readiness_backend = backend;
    m_page_readiness_backend_set = true;

    static const char hex[] = "0123456789abcdef";
    char enclave_hash[sizeof(m_target_info.mr_enclave) * 2 + 1];
    for (size_t i = 0; i < sizeof(m_target_info.mr_enclave.m); ++i)
    {
        enclave_hash[i * 2] = hex[m_target_info.mr_enclave.m[i] >> 4];
        enclave_hash[i * 2 + 1] = hex[m_target_info.mr_enclave.m[i] & 0x0f];
    }
    enclave_hash[sizeof(enclave_hash) - 1] = '\0';
    SE_TRACE(SE_TRACE_NOTICE,
             "Islands readiness backend=%s MR_ENCLAVE=%s selectors=%llu target_pages=%llu\n",
             backend == PAGE_READINESS_BACKEND_KERNEL ? "kernel" : "userspace",
             enclave_hash,
             (unsigned long long)m_page_readiness_entries.size(),
             (unsigned long long)m_page_readiness_rvas.size());
    for (size_t i = 0; i < m_page_readiness_rvas.size(); ++i)
    {
        SE_TRACE(SE_TRACE_DEBUG, "Islands readiness target RVA=0x%llx\n",
                 (unsigned long long)m_page_readiness_rvas[i]);
    }

    se_wtunlock(&m_rwlock);
    return SGX_SUCCESS;
}

CEnclave::~CEnclave()
{
    if (m_thread_pool)
    {
        delete m_thread_pool;
        m_thread_pool = NULL;
    }

    m_ocall_table = NULL;


    destory_debug_info(&m_enclave_info);
    se_fini_rwlock(&m_rwlock);
        
    se_event_destroy(m_new_thread_event);
    m_new_thread_event = NULL;
}

sgx_enclave_id_t CEnclave::get_enclave_id()
{
    return m_enclave_id;
}

uint32_t CEnclave::get_enclave_version()
{
    return m_version;
}

void CEnclave::set_dynamic_tcs_list_size(CLoader &ldr)
{
    std::vector<std::pair<tcs_t *, bool>> tcs_list = ldr.get_tcs_list();
    size_t count = 0;
    for (size_t idx = 0; idx < tcs_list.size(); ++idx)
    {
        if(tcs_list[idx].second == true)
        {
            count++;
        }
    }
    
    m_dynamic_tcs_list_size = count;
}

size_t CEnclave::get_dynamic_tcs_list_size()
{
    return m_dynamic_tcs_list_size;
}

#ifdef SE_SIM    
void CEnclave::set_global_data_sim_ptr(CLoader &ldr)
{
    m_global_data_sim_ptr = ldr.get_symbol_address("g_global_data_sim");
}

void *CEnclave::get_global_data_sim_ptr()
{
    return m_global_data_sim_ptr;
}
#endif   

uint8_t *CEnclave::get_sealed_key()
{
    return m_sealed_key;
}

void CEnclave::set_sealed_key(uint8_t *sealed_key)
{
    m_sealed_key = sealed_key;
}

bool CEnclave::set_aex_notify(bool flag)
{
    m_aex_notify = flag;
    return true;
}

bool CEnclave::get_aex_notify()
{
    return m_aex_notify;
}
    

sgx_status_t CEnclave::error_trts2urts(unsigned int trts_error)
{
    if(trts_error == (unsigned int)SE_ERROR_READ_LOCK_FAIL)
    {
        return SGX_ERROR_ENCLAVE_LOST;
    }

    //tRTS may directly return the external error code, so we don't need transfer it.
    if(EXTERNAL_ERROR != (trts_error >> MAIN_MOD_SHIFT))
    {
        SE_TRACE(SE_TRACE_WARNING, "trts return error %x, it should be urts/trts bug\n", trts_error);
        return SGX_ERROR_UNEXPECTED;
    }

    return (sgx_status_t)trts_error;
}

sgx_status_t CEnclave::ecall(const int proc, const void *ocall_table, void *ms, const bool is_switchless)
{
    if (!se_try_rdlock(&m_rwlock))
        return SGX_ERROR_ENCLAVE_LOST;

    if (m_destroyed ||
        (m_destroying.load(std::memory_order_acquire) &&
         !(proc == ECMD_UNINIT_ENCLAVE && current_destroy_uninit == this)))
    {
        se_rdunlock(&m_rwlock);
        return SGX_ERROR_ENCLAVE_LOST;
    }

    bool readiness_call = false;
    bool readiness_nonempty = false;
    const ecall_page_readiness_entry_t *readiness_entry = NULL;
    std::unique_lock<std::mutex> readiness_guard(m_page_readiness_mutex, std::defer_lock);

    if (proc >= 0)
    {
        m_page_readiness_started.store(true, std::memory_order_release);
        if (m_page_readiness_table_set)
        {
            if (!readiness_guard.try_lock())
            {
                se_rdunlock(&m_rwlock);
                return SGX_ERROR_BUSY;
            }
            if (m_page_readiness_broken)
            {
                SE_TRACE(SE_TRACE_WARNING,
                         "Islands readiness BROKEN; rejecting selector=%d\n", proc);
                se_rdunlock(&m_rwlock);
                return SGX_ERROR_INVALID_STATE;
            }
            if (is_switchless)
            {
                se_rdunlock(&m_rwlock);
                return SGX_ERROR_INVALID_FUNCTION;
            }

            std::vector<ecall_page_readiness_entry_t>::const_iterator entry =
                std::lower_bound(
                    m_page_readiness_entries.begin(),
                    m_page_readiness_entries.end(),
                    (uint64_t)proc,
                    [](const ecall_page_readiness_entry_t &candidate, uint64_t selector)
                    {
                        return candidate.selector < selector;
                    });
            if (entry == m_page_readiness_entries.end() || entry->selector != (uint64_t)proc)
            {
                se_rdunlock(&m_rwlock);
                return SGX_ERROR_INVALID_FUNCTION;
            }

            readiness_entry = &(*entry);
            readiness_call = true;
            readiness_nonempty = readiness_entry->page_count != 0;

            if (readiness_nonempty &&
                m_page_readiness_backend == PAGE_READINESS_BACKEND_USERSPACE)
            {
                if (!m_dbg_flag)
                {
                    se_rdunlock(&m_rwlock);
                    return SGX_ERROR_FEATURE_NOT_SUPPORTED;
                }

                const size_t first = (size_t)readiness_entry->first_page;
                const size_t count = (size_t)readiness_entry->page_count;
                for (size_t i = 0; i < count; ++i)
                {
                    const uint64_t rva = m_page_readiness_rvas[first + i];
                    if (!std::binary_search(m_readable_reg_rvas.begin(),
                                            m_readable_reg_rvas.end(), rva))
                    {
                        SE_TRACE(SE_TRACE_WARNING,
                                 "Islands userspace readiness rejected MR page RVA=0x%llx selector=%d\n",
                                 (unsigned long long)rva, proc);
                        se_rdunlock(&m_rwlock);
                        return SGX_ERROR_INVALID_PARAMETER;
                    }

                    SE_TRACE(SE_TRACE_DEBUG,
                             "Islands userspace readiness touching MR_ENCLAVE page RVA=0x%llx selector=%d\n",
                             (unsigned long long)rva, proc);
                    const uintptr_t address = (uintptr_t)m_start_addr + (uintptr_t)rva;
                    const volatile uint8_t touched = *(const volatile uint8_t *)address;
                    (void)touched;
                }
            }
        }
    }

    if (!readiness_call && m_switchless)
    {
        // we need to pass ocall_table pointer to the enclave when initializing switchless on trusted side.
        if (m_first_ecall && ocall_table)
        {
            // can create race condition here if we have several threads initiating "first" ecall
            // so it is possible the first switchless ecall will fallback
            m_first_ecall = false;
            // we are setting the flag here, cause otherwise it will create deadlock in sl_on_first_ecall_func_ptr()
            g_sl_funcs.sl_on_first_ecall_func_ptr(m_switchless, m_enclave_id, ocall_table);
        }

        //Do switchless ECall in a switchless way
        if (is_switchless)
        {
            int need_fallback = 0;
            sgx_status_t switchless_ret = SGX_ERROR_UNEXPECTED;

            switchless_ret = g_sl_funcs.sl_ecall_func_ptr(m_switchless, proc, ms, &need_fallback);
            if (likely(!need_fallback))
            {
                se_rdunlock(&m_rwlock);
                return switchless_ret;
            }
        }
    }

    CTrustThread *trust_thread = get_tcs(proc);
    unsigned ret = SGX_ERROR_OUT_OF_TCS;

    if (NULL != trust_thread)
    {
        if (NULL == m_ocall_table)
            m_ocall_table = (sgx_ocall_table_t *)ocall_table;

        if (proc == ECMD_UNINIT_ENCLAVE)
        {
            if (m_pthread_is_valid == true)
            {
                m_pthread_is_valid = false;
                se_event_wake(m_new_thread_event);
                pthread_join(m_pthread_tid, NULL);
            }
            /*ocall_table = m_ocall_table;

            std::vector<CTrustThread *> threads = m_thread_pool->get_thread_list();
            for (unsigned idx = 0; idx < threads.size(); ++idx)
            {
                if (trust_thread->get_tcs() == threads[idx]->get_tcs())
                {
                    continue;
                }

                uint64_t start = (uint64_t)(threads[idx]->get_tcs());
                uint64_t end = start + (1 << SE_PAGE_SHIFT);

                if (get_enclave_creator()->is_EDMM_supported(CEnclave::get_enclave_id()))
                {
                    // Change TCS permission to Read only to let driver not handle the
                    // #PF caused by TCS trim. It gives urts a chance to catch the exception
                    // and exit the ecall with an error code.
                    if(0 != mprotect((void *)start, TCS_SIZE, SI_FLAG_R))
                    {
                        se_rdunlock(&m_rwlock);
                        return SGX_ERROR_UNEXPECTED;
                    }
                    if (SGX_SUCCESS != (ret = get_enclave_creator()->trim_range(start, end)))
                    {
                        se_rdunlock(&m_rwlock);
                        return (sgx_status_t)ret;
                    }
                }
            }*/
        }

        if (readiness_call)
        {
            ReadinessTxnFrame frame(m_enclave_id);
            if (readiness_nonempty &&
                m_page_readiness_backend == PAGE_READINESS_BACKEND_KERNEL)
            {
                const uint64_t table_ptr = m_page_readiness_table_installed ? 0 :
                    (uint64_t)(uintptr_t)m_page_readiness_bytes.data();
                const uint64_t table_bytes = m_page_readiness_table_installed ? 0 :
                    (uint64_t)m_page_readiness_bytes.size();
                const int acquire_error = enclave_pages_acquire(
                    m_start_addr, readiness_entry->selector, table_ptr, table_bytes);
                if (acquire_error != 0)
                {
                    SE_TRACE(SE_TRACE_WARNING,
                             "Islands kernel ACQUIRE failed selector=%d errno=%d\n",
                             proc, acquire_error);
                    trust_thread->decrease_ref();
                    se_rdunlock(&m_rwlock);
                    return readiness_errno_to_status(acquire_error);
                }
                m_page_readiness_table_installed = true;
            }

            ret = do_ecall(proc, m_ocall_table, ms, trust_thread);

            int release_error = 0;
            if (readiness_nonempty &&
                m_page_readiness_backend == PAGE_READINESS_BACKEND_KERNEL)
            {
                release_error = enclave_pages_release(m_start_addr);
                if (release_error != 0)
                {
                    SE_TRACE(SE_TRACE_WARNING,
                             "Islands kernel RELEASE failed selector=%d errno=%d; BROKEN latched\n",
                             proc, release_error);
                    m_page_readiness_broken = true;
                }
            }

            if (SGX_PTHREAD_EXIT == ret)
                trust_thread->reset_ref();
            else
                trust_thread->decrease_ref();

            se_rdunlock(&m_rwlock);
            if (release_error != 0)
                return readiness_errno_to_status(release_error);
            return error_trts2urts(ret);
        }

        ret = do_ecall(proc, m_ocall_table, ms, trust_thread);
        if (SGX_PTHREAD_EXIT == ret)
            trust_thread->reset_ref();
        else
            trust_thread->decrease_ref();
    }

    //release the read/write lock, the only exception is enclave already be removed in ocall
    if (AbnormalTermination() || ret != SE_ERROR_READ_LOCK_FAIL)
        se_rdunlock(&m_rwlock);

    return error_trts2urts(ret);
}

int CEnclave::ocall(const unsigned int proc, const sgx_ocall_table_t *ocall_table, void *ms)
{
    int error = SGX_ERROR_UNEXPECTED;
    bool read_lock_released = false;

    if (is_builtin_ocall(proc))
    {
        if (!readiness_txn_on_current_thread(m_enclave_id))
        {
            se_rdunlock(&m_rwlock);
            read_lock_released = true;
        }
        if ((int)proc == EDMM_ALLOC)
            error = ocall_emm_alloc(ms);
        else if ((int)proc == EDMM_MODIFY)
            error = ocall_emm_modify(ms);
    }
    else
    {
        //validate the proc is within ocall_table;
        if (NULL == ocall_table || (proc >= ocall_table->count))
            return SGX_ERROR_INVALID_FUNCTION;

        if (m_switchless)
            g_sl_funcs.sl_ocall_fallback_func_ptr(m_switchless);

        if (!readiness_txn_on_current_thread(m_enclave_id))
        {
            se_rdunlock(&m_rwlock);
            read_lock_released = true;
        }
        bridge_fn_t bridge = reinterpret_cast<bridge_fn_t>(ocall_table->ocall[proc]);
        error = do_ocall(bridge, ms);
    }

    if (read_lock_released)
    {
        if (!se_try_rdlock(&m_rwlock))
        {
            //Probablly the enclave has been destroyed, so we can't get the read lock.
            error = SE_ERROR_READ_LOCK_FAIL;
        }
        else if (m_destroyed || m_destroying.load(std::memory_order_acquire))
        {
            //Teardown has started; the OCALL must not resume the ECALL.
            se_rdunlock(&m_rwlock);
            error = SE_ERROR_READ_LOCK_FAIL;
        }
    }
    return error;
}

const debug_enclave_info_t* CEnclave::get_debug_info()
{
    return &m_enclave_info;
}

//Get a new & free tcs
CTrustThread * CEnclave::get_free_tcs()
{
    CTrustThread *trust_thread = m_thread_pool->acquire_free_thread();
    return trust_thread;
}

CTrustThread * CEnclave::get_tcs(int ecall_cmd)
{
    CTrustThread *trust_thread = m_thread_pool->acquire_thread(ecall_cmd);

    return trust_thread;
}

void *fill_tcs_mini_pool_func(void *args)  
{  
     CEnclave *it = (CEnclave*)(args);
     if(it != NULL)
     {
        it->fill_tcs_mini_pool(); 
     }
     return NULL;
} 

sgx_status_t CEnclave::fill_tcs_mini_pool_fn()
{
    pthread_t tid;
    if(m_pthread_is_valid == false)
    {
       m_pthread_is_valid = true; 
       int ret = pthread_create(&tid, NULL, fill_tcs_mini_pool_func, (void *)(this));  
        if(ret != 0)
        {
            m_pthread_is_valid = false; 
            return SGX_ERROR_UNEXPECTED;
        }
        m_pthread_tid = tid;
    }
    else if(m_pthread_is_valid == true)
    {
        if(se_event_wake(m_new_thread_event) != SE_MUTEX_SUCCESS)
        {
            return SGX_ERROR_UNEXPECTED;
        }
    }
    

    return SGX_SUCCESS;
}

sgx_status_t CEnclave::fill_tcs_mini_pool()
{
    do
    {
        if(se_try_rdlock(&m_rwlock))
        {
            //Maybe the enclave has been destroyed after acquire/release m_rwlock. See CEnclave::destroy()
            if(m_destroyed || m_destroying.load(std::memory_order_acquire))
            {
                se_rdunlock(&m_rwlock);
                return SGX_ERROR_ENCLAVE_LOST;
            }
            if(m_pthread_is_valid == false)
            {
                se_rdunlock(&m_rwlock);
                return SGX_SUCCESS;
            }
            m_thread_pool->fill_tcs_mini_pool();
            se_rdunlock(&m_rwlock);
        }
        else
        {
            return SGX_ERROR_ENCLAVE_LOST;
        } 
   }while(se_event_wait(m_new_thread_event) == SE_MUTEX_SUCCESS);
   return SGX_ERROR_UNEXPECTED;
  
}

void CEnclave::destroy()
{
    se_wtlock(&m_rwlock);

    get_enclave_creator()->destroy_enclave(ENCLAVE_ID_IOCTL, m_size);

    m_destroyed = true;
    //We are going to destory m_rwlock. At this point, maybe an ecall is in progress, and try to get m_rwlock.
    //To prevent such ecall, we use m_destroyed to identify that the no ecall should going on. See CEnclave::ecall(...).
    //For new ecall to the enclave, it will return with SGX_ERROR_INVALID_ENCLAVE_ID immediately.
    se_wtunlock(&m_rwlock);
    // We should not use loader to destroy encalve because loader has been removed after successful enclave loading
    //m_loader.destroy_enclave();
}

void CEnclave::add_thread(tcs_t * const tcs, bool is_unallocated)
{
    CTrustThread *trust_thread = m_thread_pool->add_thread(tcs, this, is_unallocated);
    if(!is_unallocated)
    {
        insert_debug_tcs_info_head(&m_enclave_info, trust_thread->get_debug_info());
    }
}

void CEnclave::add_thread(CTrustThread * const trust_thread)
{
    insert_debug_tcs_info_head(&m_enclave_info, trust_thread->get_debug_info());
}


int CEnclave::set_extra_debug_info(secs_t& secs, CLoader &ldr)
{
    void *g_peak_heap_used_addr = ldr.get_symbol_address("g_peak_heap_used");
    void *g_peak_rsrv_mem_committed_addr = ldr.get_symbol_address("g_peak_rsrv_mem_committed");
    m_enclave_info.g_peak_heap_used_addr = g_peak_heap_used_addr;
    m_enclave_info.g_peak_rsrv_mem_committed_addr = g_peak_rsrv_mem_committed_addr;
    
    m_enclave_info.start_addr = secs.base;
    m_enclave_info.misc_select = secs.misc_select;

    //if elrange is not set, elrange_start_address should equal to start_addr
    if(ldr.get_elrange_size() != 0)
    {
        m_enclave_info.elrange_start_address = ldr.get_elrange_start_addr();
    }
    else
    {
        m_enclave_info.elrange_start_address = reinterpret_cast<uint64_t>(m_enclave_info.start_addr);
    }

    if(g_peak_heap_used_addr == NULL)
    {
        SE_TRACE(SE_TRACE_DEBUG, "Symbol 'g_peak_heap_used' is not found\n");
        //This error should not break loader and debugger, so the upper layer function will ignore it.
        return SGX_ERROR_INVALID_ENCLAVE;
    }
    if(g_peak_rsrv_mem_committed_addr == NULL)
    {
        SE_TRACE(SE_TRACE_DEBUG, "Symbol 'g_peak_rsrv_mem_committed' is not found\n");
        //This error should not break loader and debugger, so the upper layer function will ignore it.
        return SGX_ERROR_INVALID_ENCLAVE;
    }
    return SGX_SUCCESS;
}

void CEnclave::push_ocall_frame(ocall_frame_t* frame_point, CTrustThread *trust_thread)
{
    if(NULL == trust_thread)
    {
        return;
    }

    trust_thread->push_ocall_frame(frame_point);
}

void CEnclave::pop_ocall_frame(CTrustThread *trust_thread)
{
    if(NULL == trust_thread)
    {
        return;
    }

    trust_thread->pop_ocall_frame();
}


sgx_target_info_t CEnclave::get_target_info()
{
    return m_target_info;
}

CEnclavePool CEnclavePool::m_instance;
CEnclavePool::CEnclavePool()
{
    m_enclave_list = NULL;
    se_mutex_init(&m_enclave_mutex);
    SE_TRACE(SE_TRACE_NOTICE, "enter CEnclavePool constructor\n");
}

CEnclavePool *CEnclavePool::instance()
{
    return &m_instance;
}

int CEnclavePool::add_enclave(CEnclave *enclave)
{
    int result = TRUE;

    se_mutex_lock(&m_enclave_mutex);

    if (m_enclave_list == NULL) {
        m_enclave_list = new Node<sgx_enclave_id_t, CEnclave*>(enclave->get_enclave_id(), enclave);
    } else {
        Node<sgx_enclave_id_t, CEnclave*>* node = new Node<sgx_enclave_id_t, CEnclave*>(enclave->get_enclave_id(), enclave);
        if (m_enclave_list->InsertNext(node) == false) {
            delete node;
            SE_TRACE(SE_TRACE_WARNING, "the encalve %llx has already been added\n", enclave->get_enclave_id());
            result = FALSE;
        }
    }
    se_mutex_unlock(&m_enclave_mutex);
    return result;
}

CEnclave * CEnclavePool::get_enclave(const sgx_enclave_id_t enclave_id)
{
    se_mutex_lock(&m_enclave_mutex);
    if(m_enclave_list == NULL)
    {
        se_mutex_unlock(&m_enclave_mutex);
        return NULL;
    }
    Node<sgx_enclave_id_t, CEnclave*>* it = m_enclave_list->Find(enclave_id);
    if(it != NULL)
    {
        se_mutex_unlock(&m_enclave_mutex);
        return it->value;
    }
    else
    {
        se_mutex_unlock(&m_enclave_mutex);
        return NULL;
    }
}

CEnclave * CEnclavePool::get_enclave_with_tcs(const void * const tcs)
{
    assert(tcs != NULL);
    se_mutex_lock(&m_enclave_mutex);

    Node<sgx_enclave_id_t, CEnclave*>* it = m_enclave_list;
    for(; it != NULL; it = it->next)
    {
        void *start = it->value->get_start_address();
        void *end = GET_PTR(void, start, it->value->get_size());

        /* check start & end */
        if (tcs >= start && tcs < end) {
            se_mutex_unlock(&m_enclave_mutex);
            return it->value;
        }
    }
    se_mutex_unlock(&m_enclave_mutex);
    return NULL;
}

CEnclave * CEnclavePool::ref_enclave(const sgx_enclave_id_t enclave_id)
{
    se_mutex_lock(&m_enclave_mutex);
    if(m_enclave_list == NULL)
    {
        se_mutex_unlock(&m_enclave_mutex);
        return NULL;
    }
    Node<sgx_enclave_id_t, CEnclave*>* it = m_enclave_list->Find(enclave_id);
    if(it != NULL)
    {
        it->value->atomic_inc_ref();
        se_mutex_unlock(&m_enclave_mutex);
        return it->value;
    }
    else
    {
        se_mutex_unlock(&m_enclave_mutex);
        return NULL;
    }
}

void CEnclavePool::unref_enclave(CEnclave *enclave)
{
    //We use enclave pool lock to protect data, the lock is big, but is more secure.
    se_mutex_lock(&m_enclave_mutex);
    //The ref is increased in ref_enclave;
    uint32_t ref = enclave->atomic_dec_ref();

    //If the enclave is in zombie state, the HW enclave must have been destroyed.
    //And if the enclave is not referenced, the enclave instance will not be referenced any more,
    //so we delete the instance.
    //Another code path that delete enclave instance is in function "CEnclavePool::remove_enclave"
    if(enclave->is_zombie() && !ref)
        delete enclave;

    se_mutex_unlock(&m_enclave_mutex);
}

se_handle_t CEnclavePool::get_event(const void * const tcs)
{
    se_handle_t hevent = NULL;
    CEnclave *enclave = NULL;

    assert(tcs != NULL);
    se_mutex_lock(&m_enclave_mutex);

    Node<sgx_enclave_id_t, CEnclave*>* it = m_enclave_list;
    for(; it != NULL; it = it->next)
    {
        void *start = it->value->get_start_address();
        void *end = GET_PTR(void, start, it->value->get_size());

        /* check start & end */
        if (tcs >= start && tcs < end) {
            enclave = it->value;
            break;
        }
    }

    if (NULL != enclave)
    {
        CTrustThreadPool *pool = enclave->get_thread_pool();
        if (pool != NULL)
        {
            CTrustThread *thread = pool->get_bound_thread((const tcs_t *)tcs);
            if (thread != NULL)
                hevent = thread->get_event();
        }
    }

    se_mutex_unlock(&m_enclave_mutex);
    return hevent;
}

CEnclave* CEnclavePool::remove_enclave(const sgx_enclave_id_t enclave_id, sgx_status_t &status)
{
    status = SGX_SUCCESS;
    se_mutex_lock(&m_enclave_mutex);

    CEnclave *enclave = get_enclave(enclave_id);
    if(NULL == enclave)
    {
        status = SGX_ERROR_INVALID_ENCLAVE_ID;
        SE_TRACE(SE_TRACE_WARNING, "remove an unknown enclave\n");
        se_mutex_unlock(&m_enclave_mutex);
        return enclave;
    }
    if (enclave->is_readiness_txn_on_current_thread())
    {
        status = SGX_ERROR_INVALID_STATE;
        SE_TRACE(SE_TRACE_WARNING, "rejecting reentrant sgx_destroy_enclave during active readiness ECALL\n");
        se_mutex_unlock(&m_enclave_mutex);
        return NULL;
    }

    enclave->destroy();
    //the ref is not 0, maybe some thread is in sgx_ocall, so we can NOT delete enclave instance.
    if(enclave->get_ref())
    {
        enclave->mark_zombie();

        /* When destroy the enclave, all threads that are waiting/about to wait
         * on untrusted event need to be waked. Otherwise, they will be always
         * pending on the untrusted events, and app need to manually kill the threads.
         */
        CTrustThreadPool *pool = enclave->get_thread_pool();
        pool->wake_threads();

        enclave = NULL;
    }
    Node<sgx_enclave_id_t, CEnclave*>* it = m_enclave_list->Remove(enclave_id);
    if (it == m_enclave_list)
        m_enclave_list = it->next;
    delete it;
    se_mutex_unlock(&m_enclave_mutex);

    return enclave;
}

CEnclave *CEnclavePool::claim_destroy(const sgx_enclave_id_t enclave_id,
                                      sgx_status_t &status)
{
    status = SGX_SUCCESS;
    se_mutex_lock(&m_enclave_mutex);
    Node<sgx_enclave_id_t, CEnclave*> *node =
        m_enclave_list == NULL ? NULL : m_enclave_list->Find(enclave_id);
    CEnclave *enclave = node == NULL ? NULL : node->value;
    if (enclave == NULL)
        status = SGX_ERROR_INVALID_ENCLAVE_ID;
    else if (!enclave->mark_destroying())
    {
        status = SGX_ERROR_INVALID_STATE;
        enclave = NULL;
    }
    else
        enclave->atomic_inc_ref(); // Owner pin until the pool entry is removed.

    se_mutex_unlock(&m_enclave_mutex);
    return enclave;
}

sgx_status_t CEnclavePool::finish_destroy(CEnclave *enclave)
{
    enclave->destroy(); // May wait for an ECALL; never hold m_enclave_mutex here.

    se_mutex_lock(&m_enclave_mutex);
    Node<sgx_enclave_id_t, CEnclave*> *node =
        m_enclave_list == NULL ? NULL :
        m_enclave_list->Find(enclave->get_enclave_id());
    if (node == NULL || node->value != enclave)
    {
        se_mutex_unlock(&m_enclave_mutex);
        unref_enclave(enclave);
        return SGX_ERROR_UNEXPECTED;
    }

    Node<sgx_enclave_id_t, CEnclave*> *removed =
        m_enclave_list->Remove(enclave->get_enclave_id());
    if (removed == m_enclave_list)
        m_enclave_list = removed->next;
    delete removed;

    enclave->mark_zombie();
    CTrustThreadPool *thread_pool = enclave->get_thread_pool();
    if (thread_pool != NULL)
        thread_pool->wake_threads();
    se_mutex_unlock(&m_enclave_mutex);

    unref_enclave(enclave); // Last ref deletes after the hardware teardown.
    return SGX_SUCCESS;
}

void CEnclavePool::notify_debugger()
{
    se_mutex_lock(&m_enclave_mutex);
    if(m_enclave_list!= NULL)
    {
        Node<sgx_enclave_id_t, CEnclave*>* it = m_enclave_list;
        for(; it != NULL; it = it->next)
        {
            //send debug event to debugger when enclave is debug mode or release mode
            debug_enclave_info_t * debug_info = const_cast<debug_enclave_info_t*>((it->value)->get_debug_info());
            generate_enclave_debug_event(URTS_EXCEPTION_PREREMOVEENCLAVE, debug_info);
        }
    }
    se_mutex_unlock(&m_enclave_mutex);

}

bool CEnclave::update_trust_thread_debug_flag(void* tcs_address, uint8_t debug_flag)
{
    uint64_t debug_flag2 = (uint64_t)debug_flag;
    debug_enclave_info_t *debug_info = NULL;

    debug_info = const_cast<debug_enclave_info_t *>(get_debug_info());

    pid_t pid = getpid();

    if(debug_info->enclave_type == ET_DEBUG)
    {
       
         if(!se_write_process_mem(pid, reinterpret_cast<unsigned char *>(tcs_address) + sizeof(uint64_t), &debug_flag2, sizeof(uint64_t), NULL))
              return FALSE;

    }

    return TRUE;
}

bool CEnclave::update_debug_flag(uint8_t debug_flag)
{
    debug_tcs_info_t* tcs_list_entry = m_enclave_info.tcs_list;
    
    while(tcs_list_entry)
    {
         if(!update_trust_thread_debug_flag(tcs_list_entry->TCS_address, debug_flag))
              return FALSE;

         tcs_list_entry = tcs_list_entry->next_tcs_info;     
    }

    return TRUE;
}
