/*
 * koe_plugin.h - Embedded mruby plugin system.
 *
 * Plugins are mruby scripts that intercept koe events before they reach the
 * UI layer.  They can:
 *
 *   - Read and modify event metadata (sender, timestamp, delivery status).
 *   - Read and rewrite the plaintext body of incoming messages (for example,
 *     a translation plugin).
 *   - Suppress events entirely (for example, a keyword filter).
 *   - Generate new outbound events (for example, an auto-responder).
 *   - Access the contact book (read-only).
 *
 * Plugins CANNOT:
 *   - Access session keys or encrypted payloads directly.
 *   - Send raw packets (they request sends through the host API).
 *   - Block the event loop for more than KOE_PLUGIN_TIMEOUT_MS milliseconds.
 *   - Access the filesystem outside their designated sandbox directory.
 *   - Load native extensions (no FFI to arbitrary C from mruby).
 *
 * Each plugin lives in its own mruby VM instance for isolation.  A plugin
 * that raises an uncaught exception is logged and disabled for the session
 * but does not crash the host process.
 *
 * Plugin directory layout:
 *   <data_dir>/plugins/
 *     my_plugin/
 *       plugin.rb       required entry point
 *       manifest.json   name, version, permissions, description
 *       sandbox/        plugin's writable directory (path exposed as KOE_SANDBOX)
 *
 * mruby API surface (defined in koe_plugin_api.rb, loaded before each plugin):
 *
 *   KoeEvent.type          -> String
 *   KoeEvent.sender_id     -> String  (short ID of sender)
 *   KoeEvent.body          -> String  (plaintext, may be modified)
 *   KoeEvent.body=         -> (setter)
 *   KoeEvent.suppress!     -> marks event as suppressed (UI never sees it)
 *   KoeEvent.metadata[key] -> String
 *   KoeEvent.metadata[key]= -> (setter)
 *   Koe.send(to_short_id, body)   -> queue a text message
 *   Koe.log(message)              -> write to the plugin log
 *   Koe.contact(short_id)         -> Hash with display_name, verified
 */

#ifndef KOE_PLUGIN_H
#define KOE_PLUGIN_H

#include "koe_event.h"
#include <stdint.h>
#include <stddef.h>

#define KOE_PLUGIN_TIMEOUT_MS   100    /* max execution time per event      */
#define KOE_PLUGIN_NAME_MAX     64
#define KOE_PLUGIN_VERSION_MAX  32
#define KOE_PLUGIN_MAX          32     /* max loaded plugins at once         */

/* ---------------------------------------------------------------------- */
/* Plugin descriptor (parsed from manifest.json)                             */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_PLUGIN_PERM_READ_EVENTS    = 1 << 0,
    KOE_PLUGIN_PERM_MODIFY_EVENTS  = 1 << 1,
    KOE_PLUGIN_PERM_SEND_MESSAGES  = 1 << 2,
    KOE_PLUGIN_PERM_READ_CONTACTS  = 1 << 3,
    KOE_PLUGIN_PERM_SANDBOX_FS     = 1 << 4,
} koe_plugin_permission_t;

typedef struct {
    char     name[KOE_PLUGIN_NAME_MAX];
    char     version[KOE_PLUGIN_VERSION_MAX];
    char     description[256];
    char     author[64];
    uint32_t permissions;           /* bitmask of koe_plugin_permission_t */
    char     entry_point[256];      /* absolute path to plugin.rb         */
    char     sandbox_dir[256];      /* plugin's writable sandbox path     */
    int      enabled;
} koe_plugin_descriptor_t;

/* ---------------------------------------------------------------------- */
/* Plugin runtime (one per loaded plugin)                                    */
/* ---------------------------------------------------------------------- */

/* Opaque mruby state; defined in koe_plugin.c using mruby's mrb_state. */
typedef struct koe_plugin_vm koe_plugin_vm_t;

typedef struct {
    koe_plugin_descriptor_t desc;
    koe_plugin_vm_t        *vm;     /* heap-allocated mruby VM */
    int                     loaded; /* 1 after successful plugin.rb exec  */
    uint64_t                events_processed;
    uint64_t                events_suppressed;
    uint64_t                errors;
} koe_plugin_t;

/* Registry of all plugins. */
typedef struct {
    koe_plugin_t plugins[KOE_PLUGIN_MAX];
    int          count;
    char         plugins_dir[512];
} koe_plugin_registry_t;

/* ---------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* ---------------------------------------------------------------------- */

/*
 * koe_plugin_registry_load - Scan the plugins directory and load manifests.
 *
 * Does not execute plugin code yet — call koe_plugin_enable() for that.
 * plugins_dir: path to <data_dir>/plugins/.
 */
int koe_plugin_registry_load(koe_plugin_registry_t *reg,
                               const char            *plugins_dir);

/*
 * koe_plugin_enable - Load and execute a plugin's entry point.
 *
 * Creates a fresh mruby VM, loads the Koe standard API, then runs plugin.rb.
 * Returns 0 on success, -1 if the plugin raised an exception or exceeded
 * the timeout.
 */
int koe_plugin_enable(koe_plugin_t *plugin);

/*
 * koe_plugin_disable - Tear down a plugin's VM.
 *
 * Safe to call on an already-disabled plugin.
 */
void koe_plugin_disable(koe_plugin_t *plugin);

/*
 * koe_plugin_reload - Disable and re-enable a plugin (hot reload).
 */
int koe_plugin_reload(koe_plugin_t *plugin);

/* ---------------------------------------------------------------------- */
/* Event dispatch                                                             */
/* ---------------------------------------------------------------------- */

/*
 * koe_plugin_dispatch - Run an event through all enabled plugins in order.
 *
 * Plugins may modify ev->data or set ev->suppressed.  If any plugin
 * suppresses the event, the function returns 1 and the UI should not
 * display the event.  Returns 0 if the event survived all plugins.
 *
 * ev: the event to process (modified in place by plugins).
 */
int koe_plugin_dispatch(koe_plugin_registry_t *reg, koe_event_t *ev);

/* ---------------------------------------------------------------------- */
/* Plugin API callbacks (called FROM mruby INTO C)                          */
/* ---------------------------------------------------------------------- */

/*
 * These are registered as mruby native methods in koe_plugin.c.
 * Exposed here so koe-chat (Rust) can instrument them for testing.
 */
typedef void (*koe_plugin_send_fn)(const uint8_t *to_pk,
                                    const char    *body,
                                    void          *ctx);

typedef void (*koe_plugin_log_fn)(const char *plugin_name,
                                   const char *message,
                                   void       *ctx);

/*
 * koe_plugin_set_send_cb - Set the function called when a plugin requests
 *                          a message send (Koe.send in Ruby).
 */
void koe_plugin_set_send_cb(koe_plugin_registry_t *reg,
                              koe_plugin_send_fn     fn,
                              void                  *ctx);

/*
 * koe_plugin_set_log_cb - Set the function called when a plugin logs.
 */
void koe_plugin_set_log_cb(koe_plugin_registry_t *reg,
                             koe_plugin_log_fn      fn,
                             void                  *ctx);

/* ---------------------------------------------------------------------- */
/* Introspection                                                              */
/* ---------------------------------------------------------------------- */

/*
 * koe_plugin_stats - Fill a human-readable stats string for a plugin.
 *
 * buf must be at least 256 bytes.
 */
void koe_plugin_stats(const koe_plugin_t *plugin, char *buf, int buf_len);

#endif /* KOE_PLUGIN_H */
