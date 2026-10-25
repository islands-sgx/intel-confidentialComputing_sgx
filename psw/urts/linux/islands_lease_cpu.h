#ifndef ISLANDS_LEASE_CPU_H
#define ISLANDS_LEASE_CPU_H

#if defined(__GNUC__)
#define ISLANDS_LEASE_HIDDEN __attribute__((visibility("hidden")))
#else
#define ISLANDS_LEASE_HIDDEN
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* begin: 1 when this call owns a lease frame, 0 when affinity is inactive,
 * and -errno when the lease could not be initialized. */
ISLANDS_LEASE_HIDDEN int islands_lease_cpu_begin(int fn);
ISLANDS_LEASE_HIDDEN int islands_lease_cpu_enter(void);
ISLANDS_LEASE_HIDDEN int islands_lease_cpu_exit(void);
ISLANDS_LEASE_HIDDEN int islands_lease_cpu_refresh_host(void);
ISLANDS_LEASE_HIDDEN int islands_lease_cpu_end(void);

#ifdef __cplusplus
}

class IslandsLeaseCpuScope
{
public:
    explicit IslandsLeaseCpuScope(int fn)
        : m_begin_status(islands_lease_cpu_begin(fn)), m_finished(false)
    {
    }

    ~IslandsLeaseCpuScope()
    {
        if (m_begin_status > 0 && !m_finished)
            (void)islands_lease_cpu_end();
    }

    int begin_error() const
    {
        return m_begin_status < 0 ? -m_begin_status : 0;
    }

    bool active() const
    {
        return m_begin_status > 0;
    }

    int enter() const
    {
        return active() ? islands_lease_cpu_enter() : 0;
    }

    int finish()
    {
        if (!active() || m_finished)
            return 0;
        m_finished = true;
        return islands_lease_cpu_end();
    }

private:
    int m_begin_status;
    bool m_finished;
};
#endif

#endif
