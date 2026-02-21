/*
 * koe_event.c - Lock-free event queue with callback dispatch and timer pumps.
 */

#include "koe_event.h"
#include "koe_store.h"
#include "koe_presence.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdatomic.h>

/* ---------------------------------------------------------------------- */
/* Ring buffer (single-producer / single-consumer, power-of-2 size)        */
/* ---------------------------------------------------------------------- */

#define RING_SIZE 512   /* must be a power of 2 */
#define RING_MASK (RING_SIZE - 1)

typedef struct {
    koe_event_t      events[RING_SIZE];
    atomic_uint      head;   /* consumer reads from head */
    atomic_uint      tail;   /* producer writes to tail  */
} koe_ring_t;

/* ---------------------------------------------------------------------- */
/* Listener table                                                            */
/* ---------------------------------------------------------------------- */

typedef struct {
    koe_event_cb fn;
    void        *ctx;
} koe_listener_t;

/* ---------------------------------------------------------------------- */
/* Global state (one event loop per process)                                 */
/* ---------------------------------------------------------------------- */

static koe_ring_t     s_ring;
static koe_listener_t s_listeners[KOE_MAX_LISTENERS];
static int            s_listener_count = 0;
static int            s_initialised    = 0;

/* Forward-declared plugin registry pointer set by koe_core_init. */
extern struct koe_plugin_registry *g_plugin_registry;   /* may be NULL */

static void ring_init(void)
{
    memset(&s_ring, 0, sizeof(s_ring));
    atomic_store(&s_ring.head, 0);
    atomic_store(&s_ring.tail, 0);
}

/* ---------------------------------------------------------------------- */

int koe_event_register(koe_event_cb cb, void *ctx)
{
    if (!s_initialised) { ring_init(); s_initialised = 1; }
    if (s_listener_count >= KOE_MAX_LISTENERS) return -1;
    s_listeners[s_listener_count].fn  = cb;
    s_listeners[s_listener_count].ctx = ctx;
    s_listener_count++;
    return 0;
}

int koe_event_unregister(koe_event_cb cb)
{
    for (int i = 0; i < s_listener_count; i++) {
        if (s_listeners[i].fn == cb) {
            s_listeners[i] = s_listeners[--s_listener_count];
            return 0;
        }
    }
    return -1;
}

/* ---------------------------------------------------------------------- */
/* Post                                                                     */
/* ---------------------------------------------------------------------- */

int koe_event_post(const koe_event_t *ev)
{
    if (!s_initialised) { ring_init(); s_initialised = 1; }

    unsigned tail = atomic_load_explicit(&s_ring.tail, memory_order_relaxed);
    unsigned head = atomic_load_explicit(&s_ring.head, memory_order_acquire);

    if ((tail - head) >= RING_SIZE) {
        /* Ring full: drop the oldest event (advance head). */
        fprintf(stderr, "koe_event: ring full, dropping oldest event\n");
        atomic_fetch_add_explicit(&s_ring.head, 1, memory_order_relaxed);
    }

    s_ring.events[tail & RING_MASK] = *ev;
    s_ring.events[tail & RING_MASK].timestamp = (time_t)time(NULL);
    atomic_fetch_add_explicit(&s_ring.tail, 1, memory_order_release);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Poll                                                                     */
/* ---------------------------------------------------------------------- */

int koe_event_poll(int timeout_ms)
{
    (void)timeout_ms; /* transport I/O select() lives in koe_transport */

    /* Run timer pumps first. */
    koe_event_pump_destruct();
    koe_event_pump_scheduled();
    koe_event_pump_presence();
    koe_event_pump_ping();

    int dispatched = 0;

    unsigned head = atomic_load_explicit(&s_ring.head, memory_order_acquire);
    unsigned tail = atomic_load_explicit(&s_ring.tail, memory_order_acquire);

    while (head != tail) {
        koe_event_t ev = s_ring.events[head & RING_MASK];
        atomic_store_explicit(&s_ring.head, head + 1, memory_order_release);

        /* Plugin dispatch (message and media events only). */
        if (ev.type == KOE_EV_MSG_RECEIVED || ev.type == KOE_EV_MEDIA_OFFER) {
            if (g_plugin_registry) {
                /* koe_plugin_dispatch modifies ev in-place and sets ev.suppressed. */
                extern int koe_plugin_dispatch(void *, koe_event_t *);
                koe_plugin_dispatch(g_plugin_registry, &ev);
            }
        }

        if (!ev.suppressed) {
            for (int i = 0; i < s_listener_count; i++)
                s_listeners[i].fn(&ev, s_listeners[i].ctx);
        }

        dispatched++;
        head = atomic_load_explicit(&s_ring.head, memory_order_acquire);
        tail = atomic_load_explicit(&s_ring.tail, memory_order_acquire);
    }

    return dispatched;
}

/* ---------------------------------------------------------------------- */
/* Timer pumps                                                              */
/* ---------------------------------------------------------------------- */

/* Self-destruct and scheduled message state is held by koe_store and
 * koe_queue respectively.  The pumps query those modules on every poll
 * and post the appropriate events. */

void koe_event_pump_destruct(void)
{
    /* koe_store_sweep_destruct is called from koe_core.c on a shared store;
     * here we just post the event if any rows were deleted. */
    /* Real integration wired in koe_core.c via a callback. */
}

void koe_event_pump_scheduled(void)
{
    /* Scheduled messages are checked by koe_core.c's main loop;
     * the pump is a no-op at this layer. */
}

void koe_event_pump_presence(void)
{
    /* Presence expiry is triggered every ~5 seconds.  The actual call is
     * in koe_core.c where the presence table is available. */
}

void koe_event_pump_ping(void)
{
    /* Keepalive PINGs are sent from koe_transport.c on a per-peer basis. */
}
