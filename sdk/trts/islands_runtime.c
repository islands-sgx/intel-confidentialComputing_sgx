/*
 * Islands trusted Routine boundary ABI.
 *
 * This file is applied to the pinned SDK source.  The single active bit is
 * deliberately a global hidden object so the OENTRY assembly and boundary
 * calls bind the same storage.
 */
#include <stdint.h>

_Atomic uint32_t __islands_active
    __attribute__((aligned(4), section(".nipd"), visibility("hidden"))) = 0;

extern int EDMM_supported;

extern void abort(void)
    __attribute__((noreturn, visibility("hidden")));

void islands_routine_enter(uint64_t routine_id)
{
    uint32_t expected = 0;
    (void)routine_id;
    if (EDMM_supported != 0)
        abort();
    if (__atomic_compare_exchange_n((uint32_t *)&__islands_active, &expected, 1,
                                     0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    abort();
}

void islands_routine_exit(uint64_t routine_id)
{
    uint32_t expected = 1;
    (void)routine_id;
    if (!__atomic_compare_exchange_n((uint32_t *)&__islands_active, &expected, 0,
                                      0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        abort();
}
