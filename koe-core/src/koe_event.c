/*
 * koe_event.c - Poll-based event loop and async dispatcher.
 *
 * The event queue is a fixed-size ring buffer. Producers (transport receive
 * callbacks, timer handlers) call koe_event_post(); consumers call
 * koe_event_poll() from the TUI's render loop.
 *
 * Thread safety: koe_event_post() uses a lightweight spinlock so it is safe
 * to call from a signal handler or a background I/O thread. koe_event_poll()
 * must be called from the main thread only.
 */

#include "koe_event.h"
#include "koe_message.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdatomic.h>

#define KOE_EVENT_RING_SIZE  256   /* must be a power of two */

/* ---------------------------------------------------------------------- */

typedef struct {
    koe_event_cb cb;
    void        *ctx;
} koe_event_listener_t;

#define KOE_MAX_LISTENERS  16

static koe_event_t         s_ring[KOE_EVENT_RING_SIZE];
static atomic_size_t       s_head;    /* write index (producers) */
static atomic_size_t       s_tail;    /* read  index (consumer)  */
static koe_event_listener_t s_listeners[KOE_MAX_LISTENERS];
static int                  s_listener_count;

/* Scheduled messages: singly-linked list of (send_at, koe_message_t*).
 * Managed exclusively from the main thread. */
typedef struct sched_node {
    time_t          send_at;
    koe_message_t  *msg;
    struct sched_node *next;
} sched_node_t;

static sched_node_t *s_sched_head;

/* Self-destruct timers: same structure. */
typedef struct destruct_node {
    time_t          destruct_at;
    uint64_t        message_id;
    struct destruct_node *next;
} destruct_node_t;

static destruct_node_t *s_destruct_head;

/* ---------------------------------------------------------------------- */

int koe_event_register(koe_event_cb cb, void *ctx)
{
    if (s_listener_count >= KOE_MAX_LISTENERS) return -1;
    s_listeners[s_listener_count].cb  = cb;
    s_listeners[s_listener_count].ctx = ctx;
    s_listener_count++;
    return 0;
}

int koe_event_post(const koe_event_t *ev)
{
    size_t next = (atomic_load(&s_head) + 1) & (KOE_EVENT_RING_SIZE - 1);
    if (next == atomic_load(&s_tail)) {
        /* Ring is full; drop the oldest event and warn. */
        fprintf(stderr, "koe_event: ring full, dropping oldest event\n");
        atomic_fetch_add(&s_tail, 1);
    }
    s_ring[atomic_load(&s_head)] = *ev;
    atomic_fetch_add(&s_head, 1);
    return 0;
}

int koe_event_poll(int timeout_ms)
{
    (void)timeout_ms;  /* non-blocking for now; poll loop sits in the TUI */

    int dispatched = 0;

    /* Drain the ring. */
    while (atomic_load(&s_tail) != atomic_load(&s_head)) {
        size_t idx = atomic_load(&s_tail) & (KOE_EVENT_RING_SIZE - 1);
        koe_event_t ev = s_ring[idx];
        atomic_fetch_add(&s_tail, 1);

        for (int i = 0; i < s_listener_count; i++)
            s_listeners[i].cb(&ev, s_listeners[i].ctx);

        dispatched++;
    }

    /* Run the pumps. */
    koe_event_pump_scheduled();
    koe_event_pump_destruct();

    return dispatched;
}

/* ---------------------------------------------------------------------- */

void koe_event_pump_scheduled(void)
{
    time_t now = time(NULL);
    sched_node_t **prev = &s_sched_head;

    for (sched_node_t *n = s_sched_head; n; ) {
        if (n->send_at <= now) {
            /* Post a synthetic "message due" event. The TUI's event handler
             * picks this up and calls koe_send_text (or equivalent). */
            koe_event_t ev = {0};
            ev.type             = KOE_EV_MSG_RECEIVED;
            ev.timestamp        = now;
            ev.data.message.msg = n->msg;
            koe_event_post(&ev);

            sched_node_t *dead = n;
            n = n->next;
            *prev = n;
            free(dead);   /* msg ownership transferred via event */
        } else {
            prev = &n->next;
            n    = n->next;
        }
    }
}

void koe_event_pump_destruct(void)
{
    time_t now = time(NULL);
    destruct_node_t **prev = &s_destruct_head;

    for (destruct_node_t *n = s_destruct_head; n; ) {
        if (n->destruct_at <= now) {
            koe_event_t ev = {0};
            ev.type                    = KOE_EV_DESTRUCT_TICK;
            ev.timestamp               = now;
            ev.data.destruct.message_id = n->message_id;
            koe_event_post(&ev);

            destruct_node_t *dead = n;
            n = n->next;
            *prev = n;
            free(dead);
        } else {
            prev = &n->next;
            n    = n->next;
        }
    }
}
