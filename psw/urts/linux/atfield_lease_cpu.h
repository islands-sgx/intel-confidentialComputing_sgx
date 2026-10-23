#ifndef ATFIELD_LEASE_CPU_H
#define ATFIELD_LEASE_CPU_H

#if defined(__GNUC__)
#define ATFIELD_LEASE_HIDDEN __attribute__((visibility("hidden")))
#else
#define ATFIELD_LEASE_HIDDEN
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* begin: 1 when this call owns a lease frame, 0 when affinity is inactive,
 * and -errno when the lease could not be initialized. */
ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_begin(int fn);
ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_enter(void);
ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_exit(void);
ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_refresh_host(void);
ATFIELD_LEASE_HIDDEN int atfield_lease_cpu_end(void);

#ifdef __cplusplus
}

class AtfieldLeaseCpuScope
{
public:
    explicit AtfieldLeaseCpuScope(int fn)
        : m_begin_status(atfield_lease_cpu_begin(fn)), m_finished(false)
    {
    }

    ~AtfieldLeaseCpuScope()
    {
        if (m_begin_status > 0 && !m_finished)
            (void)atfield_lease_cpu_end();
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
        return active() ? atfield_lease_cpu_enter() : 0;
    }

    int finish()
    {
        if (!active() || m_finished)
            return 0;
        m_finished = true;
        return atfield_lease_cpu_end();
    }

private:
    int m_begin_status;
    bool m_finished;
};
#endif

#endif

