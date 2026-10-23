#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "atfield_lease_cpu.h"
#include "rts_cmd.h"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>

namespace
{
static const size_t kMaxAffinityCpus = 1024 * 1024;
static const size_t kMaxLeaseDepth = 64;

struct LeaseConfig
{
    bool enabled;
    int cpu;
    int error;
};

struct LeaseFrame
{
    bool entered_on_lease_cpu;
};

struct LeaseState
{
    bool active;
    bool on_lease_cpu;
    int cpu;
    int depth;
    int sticky_error;
    size_t set_size;
    cpu_set_t *host_mask;
    cpu_set_t *lease_mask;
    cpu_set_t *scratch_mask;
    LeaseFrame frames[kMaxLeaseDepth];

    LeaseState()
        : active(false),
          on_lease_cpu(false),
          cpu(-1),
          depth(0),
          sticky_error(0),
          set_size(0),
          host_mask(NULL),
          lease_mask(NULL),
          scratch_mask(NULL)
    {
    }

    ~LeaseState()
    {
        if (active && host_mask != NULL)
            (void)set_host_mask(*this, true);
        release_masks();
    }

    void release_masks()
    {
        if (host_mask != NULL)
            CPU_FREE(host_mask);
        if (lease_mask != NULL)
            CPU_FREE(lease_mask);
        if (scratch_mask != NULL)
            CPU_FREE(scratch_mask);
        active = false;
        on_lease_cpu = false;
        cpu = -1;
        depth = 0;
        sticky_error = 0;
        set_size = 0;
        host_mask = NULL;
        lease_mask = NULL;
        scratch_mask = NULL;
    }

    static int set_host_mask(LeaseState &state, bool force);
};

static LeaseConfig g_config = {false, -1, 0};
static pthread_once_t g_config_once = PTHREAD_ONCE_INIT;
static thread_local LeaseState g_state;

static void log_error(const char *message, size_t length)
{
    const ssize_t ignored = write(STDERR_FILENO, message, length);
    (void)ignored;
}

static void initialize_config()
{
    const char *value = getenv("ATFIELD_LEASE_CPU");
    if (value == NULL)
        return;

    if (*value < '0' || *value > '9')
    {
        g_config.error = EINVAL;
        static const char message[] =
            "ATFIELD_LEASE_CPU: expected a decimal CPU index\n";
        log_error(message, sizeof(message) - 1);
        return;
    }

    char *end = NULL;
    errno = 0;
    long cpu = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        cpu < 0 || cpu > INT_MAX || cpu >= (long)kMaxAffinityCpus)
    {
        g_config.error = EINVAL;
        static const char message[] =
            "ATFIELD_LEASE_CPU: invalid CPU index\n";
        log_error(message, sizeof(message) - 1);
        return;
    }

    g_config.enabled = true;
    g_config.cpu = (int)cpu;
}

static int get_config()
{
    int error = pthread_once(&g_config_once, initialize_config);
    if (error != 0)
        return -error;
    if (g_config.error != 0)
        return -g_config.error;
    return g_config.enabled ? 1 : 0;
}

static int capture_masks(int cpu, cpu_set_t **host_mask,
                         cpu_set_t **lease_mask, cpu_set_t **scratch_mask,
                         size_t *set_size)
{
    long configured = sysconf(_SC_NPROCESSORS_CONF);
    size_t ncpus = configured > 0 ? (size_t)configured : 128;
    if (ncpus < 128)
        ncpus = 128;
    if (ncpus <= (size_t)cpu)
        ncpus = (size_t)cpu + 1;
    if (ncpus > kMaxAffinityCpus)
        return EINVAL;

    cpu_set_t *host = NULL;
    size_t bytes = 0;
    for (;;)
    {
        bytes = CPU_ALLOC_SIZE(ncpus);
        host = CPU_ALLOC(ncpus);
        if (host == NULL)
            return ENOMEM;
        CPU_ZERO_S(bytes, host);

        if (sched_getaffinity(0, bytes, host) == 0)
            break;

        int error = errno;
        CPU_FREE(host);
        host = NULL;
        if (error != EINVAL || ncpus >= kMaxAffinityCpus)
            return error;
        ncpus *= 2;
        if (ncpus > kMaxAffinityCpus)
            ncpus = kMaxAffinityCpus;
    }

    if (CPU_ISSET_S(cpu, bytes, host))
    {
        CPU_FREE(host);
        return EINVAL;
    }

    cpu_set_t *lease = CPU_ALLOC(ncpus);
    cpu_set_t *scratch = CPU_ALLOC(ncpus);
    if (lease == NULL || scratch == NULL)
    {
        if (lease != NULL)
            CPU_FREE(lease);
        if (scratch != NULL)
            CPU_FREE(scratch);
        CPU_FREE(host);
        return ENOMEM;
    }
    CPU_ZERO_S(bytes, lease);
    CPU_SET_S(cpu, bytes, lease);
    CPU_ZERO_S(bytes, scratch);

    *host_mask = host;
    *lease_mask = lease;
    *scratch_mask = scratch;
    *set_size = bytes;
    return 0;
}

int LeaseState::set_host_mask(LeaseState &state, bool force)
{
    if (!state.active || (!force && !state.on_lease_cpu))
        return 0;

    int first_error = 0;
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        if (sched_setaffinity(0, state.set_size, state.host_mask) == 0)
        {
            state.on_lease_cpu = false;
            return first_error;
        }

        int error = errno;
        if (first_error == 0)
            first_error = error;
        state.sticky_error = first_error;
        static const char message[] =
            "ATFIELD_LEASE_CPU: restoring host affinity failed\n";
        log_error(message, sizeof(message) - 1);
    }

    static const char fatal_message[] =
        "ATFIELD_LEASE_CPU: cannot restore host affinity; terminating\n";
    log_error(fatal_message, sizeof(fatal_message) - 1);
    abort();
}

static int set_lease_mask(LeaseState &state)
{
    if (!state.active || state.depth == 0)
        return 0;
    if (state.sticky_error != 0)
    {
        (void)LeaseState::set_host_mask(state, true);
        return state.sticky_error;
    }
    if (state.on_lease_cpu)
        return 0;

    if (sched_setaffinity(0, state.set_size, state.lease_mask) == 0)
    {
        state.on_lease_cpu = true;
        return 0;
    }

    int error = errno;
    state.sticky_error = error;
    static const char message[] =
        "ATFIELD_LEASE_CPU: selecting leased CPU failed\n";
    log_error(message, sizeof(message) - 1);
    (void)LeaseState::set_host_mask(state, true);
    return error;
}

static int refresh_host_mask(LeaseState &state)
{
    if (!state.active || state.depth == 0)
        return 0;
    if (state.on_lease_cpu)
        return EBUSY;

    CPU_ZERO_S(state.set_size, state.scratch_mask);
    if (sched_getaffinity(0, state.set_size, state.scratch_mask) != 0)
    {
        int error = errno;
        state.sticky_error = error;
        static const char message[] =
            "ATFIELD_LEASE_CPU: refreshing host affinity failed\n";
        log_error(message, sizeof(message) - 1);
        (void)LeaseState::set_host_mask(state, true);
        return error;
    }

    if (CPU_ISSET_S(state.cpu, state.set_size, state.scratch_mask))
    {
        state.sticky_error = EINVAL;
        static const char message[] =
            "ATFIELD_LEASE_CPU: host affinity includes leased CPU\n";
        log_error(message, sizeof(message) - 1);
        (void)LeaseState::set_host_mask(state, true);
        return EINVAL;
    }

    cpu_set_t *old_host = state.host_mask;
    state.host_mask = state.scratch_mask;
    state.scratch_mask = old_host;
    return 0;
}

static int enter_scope(LeaseState &state)
{
    if (state.depth >= (int)kMaxLeaseDepth)
        return EOVERFLOW;
    state.frames[state.depth].entered_on_lease_cpu = state.on_lease_cpu;
    ++state.depth;
    return 0;
}
}

extern "C" ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_begin(int fn)
{
    LeaseState &state = g_state;

    if (state.active && state.depth > 0)
    {
        if (state.sticky_error != 0)
            return -state.sticky_error;
        if (fn >= 0 || fn == ECMD_EXCEPT)
        {
            if (!state.on_lease_cpu)
            {
                int refresh_error = refresh_host_mask(state);
                if (refresh_error != 0)
                    return -refresh_error;
            }
            int error = enter_scope(state);
            return error == 0 ? 1 : -error;
        }
        return 0;
    }

    if (state.active && state.depth == 0)
    {
        int error = LeaseState::set_host_mask(state, true);
        if (error != 0)
            return -error;
        state.release_masks();
    }

    if (fn < 0 && fn != ECMD_EXCEPT)
        return 0;
    if (fn == ECMD_EXCEPT)
        return 0;

    int config = get_config();
    if (config <= 0)
        return config;

    cpu_set_t *host_mask = NULL;
    cpu_set_t *lease_mask = NULL;
    cpu_set_t *scratch_mask = NULL;
    size_t set_size = 0;
    int error = capture_masks(g_config.cpu, &host_mask, &lease_mask,
                             &scratch_mask, &set_size);
    if (error != 0)
    {
        static const char message[] =
            "ATFIELD_LEASE_CPU: reading host affinity or validating CPU failed\n";
        log_error(message, sizeof(message) - 1);
        return -error;
    }

    state.active = true;
    state.on_lease_cpu = false;
    state.cpu = g_config.cpu;
    state.depth = 0;
    state.sticky_error = 0;
    state.set_size = set_size;
    state.host_mask = host_mask;
    state.lease_mask = lease_mask;
    state.scratch_mask = scratch_mask;

    error = enter_scope(state);
    if (error != 0)
    {
        state.release_masks();
        return -error;
    }
    return 1;
}

extern "C" ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_enter(void)
{
    return set_lease_mask(g_state);
}

extern "C" ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_exit(void)
{
    LeaseState &state = g_state;
    if (!state.active || state.depth == 0)
        return 0;

    int first_error = state.sticky_error;
    int error = LeaseState::set_host_mask(state, false);
    if (first_error != 0)
        return first_error;
    if (error != 0)
        state.sticky_error = error;
    return error;
}

extern "C" ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_refresh_host(void)
{
    return refresh_host_mask(g_state);
}

extern "C" ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_end(void)
{
    LeaseState &state = g_state;
    if (!state.active || state.depth <= 0)
        return EINVAL;

    LeaseFrame frame = state.frames[state.depth - 1];
    int error = 0;
    if (state.sticky_error != 0)
    {
        error = state.sticky_error;
        (void)LeaseState::set_host_mask(state, true);
    }
    else if (frame.entered_on_lease_cpu)
    {
        error = set_lease_mask(state);
    }
    else
    {
        error = LeaseState::set_host_mask(state, false);
    }

    if (error != 0 && state.sticky_error == 0)
        state.sticky_error = error;

    --state.depth;
    if (state.depth == 0)
    {
        int restore_error = LeaseState::set_host_mask(state, state.on_lease_cpu);
        if (error == 0 && restore_error != 0)
            error = restore_error;
        if (state.sticky_error != 0 && error == 0)
            error = state.sticky_error;

        if (!state.on_lease_cpu)
            state.release_masks();
    }

    return error;
}

