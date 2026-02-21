/*
 * koe_plugin.c - mruby embedded plugin system.
 *
 * Each plugin runs in its own mrb_state for isolation.  The Koe host API
 * is exposed as a native C module called "Koe" and a data class "KoeEvent".
 *
 * Build dependency: mruby (https://github.com/mruby/mruby)
 *   Termux: pkg install mruby-dev
 *   Debian: compile from source with the minimum build configuration.
 *
 * If mruby is not available, the plugin system compiles to safe no-ops
 * via the KOE_NO_MRUBY guard.
 */

#include "koe_plugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef KOE_NO_MRUBY
#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mruby/hash.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#endif

/* ---------------------------------------------------------------------- */
/* Opaque VM type                                                            */
/* ---------------------------------------------------------------------- */

struct koe_plugin_vm {
#ifndef KOE_NO_MRUBY
    mrb_state *mrb;
#else
    int dummy;
#endif
    koe_event_t *current_event;   /* set during koe_plugin_dispatch */
};

/* ---------------------------------------------------------------------- */
/* Global send / log callbacks                                               */
/* ---------------------------------------------------------------------- */

static koe_plugin_send_fn s_send_fn = NULL;
static void              *s_send_ctx = NULL;
static koe_plugin_log_fn  s_log_fn  = NULL;
static void              *s_log_ctx = NULL;

/* ---------------------------------------------------------------------- */
/* Plugin API Ruby constants (loaded before each plugin)                    */
/* ---------------------------------------------------------------------- */

static const char KOE_PLUGIN_API_RB[] =
    "module KoeEvent\n"
    "  class << self\n"
    "    attr_accessor :type, :sender_id, :body, :suppressed, :metadata\n"
    "    def suppress!\n"
    "      @suppressed = true\n"
    "    end\n"
    "  end\n"
    "  self.metadata = {}\n"
    "  self.suppressed = false\n"
    "end\n"
    "\n"
    "module Koe\n"
    "  def self.send(to_short_id, body)\n"
    "    _native_send(to_short_id, body)\n"
    "  end\n"
    "  def self.log(msg)\n"
    "    _native_log(msg.to_s)\n"
    "  end\n"
    "  def self.contact(short_id)\n"
    "    { 'short_id' => short_id, 'display_name' => '?', 'verified' => false }\n"
    "  end\n"
    "end\n";

/* ---------------------------------------------------------------------- */
/* Registry management                                                       */
/* ---------------------------------------------------------------------- */

int koe_plugin_registry_load(koe_plugin_registry_t *reg, const char *plugins_dir)
{
    memset(reg, 0, sizeof(*reg));
    strncpy(reg->plugins_dir, plugins_dir, sizeof(reg->plugins_dir) - 1);

    /* Scan for subdirectories containing a manifest.json. */
    /* Full directory scanning uses POSIX opendir/readdir. */
    /* For brevity the actual directory scan is delegated to koe_core.c
     * which calls koe_plugin_registry_load() per discovered plugin dir.
     * This function just initialises the registry. */
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Plugin lifecycle                                                          */
/* ---------------------------------------------------------------------- */

int koe_plugin_enable(koe_plugin_t *plugin)
{
#ifdef KOE_NO_MRUBY
    (void)plugin;
    fprintf(stderr, "koe_plugin: mruby not compiled in\n");
    return -1;
#else
    plugin->vm = calloc(1, sizeof(koe_plugin_vm_t));
    if (!plugin->vm) return -1;

    plugin->vm->mrb = mrb_open();
    if (!plugin->vm->mrb) {
        free(plugin->vm);
        plugin->vm = NULL;
        return -1;
    }

    mrb_state *mrb = plugin->vm->mrb;

    /* Load the Koe host API. */
    mrb_load_string(mrb, KOE_PLUGIN_API_RB);
    if (mrb->exc) {
        fprintf(stderr, "koe_plugin: API load error in plugin '%s'\n",
                plugin->desc.name);
        mrb_close(mrb);
        free(plugin->vm);
        plugin->vm = NULL;
        return -1;
    }

    /* Load the plugin entry point. */
    FILE *f = fopen(plugin->desc.entry_point, "r");
    if (!f) {
        fprintf(stderr, "koe_plugin: cannot open %s\n", plugin->desc.entry_point);
        mrb_close(mrb);
        free(plugin->vm);
        plugin->vm = NULL;
        return -1;
    }

    mrb_load_file(mrb, f);
    fclose(f);

    if (mrb->exc) {
        fprintf(stderr, "koe_plugin: load error in plugin '%s'\n",
                plugin->desc.name);
        mrb_close(mrb);
        free(plugin->vm);
        plugin->vm = NULL;
        return -1;
    }

    plugin->loaded = 1;
    return 0;
#endif
}

void koe_plugin_disable(koe_plugin_t *plugin)
{
#ifndef KOE_NO_MRUBY
    if (plugin->vm) {
        if (plugin->vm->mrb) mrb_close(plugin->vm->mrb);
        free(plugin->vm);
        plugin->vm = NULL;
    }
#endif
    plugin->loaded = 0;
}

int koe_plugin_reload(koe_plugin_t *plugin)
{
    koe_plugin_disable(plugin);
    return koe_plugin_enable(plugin);
}

/* ---------------------------------------------------------------------- */
/* Event dispatch                                                            */
/* ---------------------------------------------------------------------- */

int koe_plugin_dispatch(koe_plugin_registry_t *reg, koe_event_t *ev)
{
    if (!reg || !ev) return 0;

    for (int i = 0; i < reg->count; i++) {
        koe_plugin_t *p = &reg->plugins[i];
        if (!p->loaded || !p->desc.enabled) continue;
        if (!(p->desc.permissions & KOE_PLUGIN_PERM_MODIFY_EVENTS)) continue;

#ifndef KOE_NO_MRUBY
        mrb_state *mrb = p->vm->mrb;
        p->vm->current_event = ev;

        /* Set KoeEvent.type and KoeEvent.body from the event. */
        mrb_value koe_event = mrb_const_get(mrb, mrb_obj_value(mrb->object_class),
                                              mrb_intern_lit(mrb, "KoeEvent"));

        /* type */
        char type_str[32];
        snprintf(type_str, sizeof(type_str), "%d", (int)ev->type);
        mrb_funcall(mrb, koe_event, "type=", 1, mrb_str_new_cstr(mrb, type_str));

        /* body (only for message events) */
        if (ev->type == KOE_EV_MSG_RECEIVED) {
            mrb_value body = mrb_str_new(mrb,
                                          (const char *)ev->data.message.body,
                                          (mrb_int)ev->data.message.body_len);
            mrb_funcall(mrb, koe_event, "body=", 1, body);
        }

        mrb_funcall(mrb, koe_event, "suppressed=", 1, mrb_false_value());

        /* Call the plugin's on_event method if defined. */
        if (mrb_respond_to(mrb, koe_event, mrb_intern_lit(mrb, "on_event"))) {
            mrb_funcall(mrb, koe_event, "on_event", 0);
        }

        /* Check if the event was suppressed or body was modified. */
        mrb_value suppressed = mrb_funcall(mrb, koe_event, "suppressed", 0);
        if (mrb_test(suppressed)) {
            ev->suppressed = 1;
            p->events_suppressed++;
        }

        if (ev->type == KOE_EV_MSG_RECEIVED && !ev->suppressed) {
            mrb_value new_body = mrb_funcall(mrb, koe_event, "body", 0);
            if (mrb_string_p(new_body)) {
                const char *body_str = mrb_str_to_cstr(mrb, new_body);
                size_t      body_len = strlen(body_str);
                if (body_len < sizeof(ev->data.message.body)) {
                    memcpy(ev->data.message.body, body_str, body_len);
                    ev->data.message.body_len = body_len;
                }
            }
        }

        if (mrb->exc) {
            fprintf(stderr, "koe_plugin: exception in plugin '%s' (event %d)\n",
                    p->desc.name, (int)ev->type);
            mrb->exc = NULL;
            p->errors++;
        }

        p->events_processed++;
        p->vm->current_event = NULL;
#else
        (void)ev;
#endif
    }

    return ev->suppressed ? 1 : 0;
}

/* ---------------------------------------------------------------------- */
/* Callback setters                                                          */
/* ---------------------------------------------------------------------- */

void koe_plugin_set_send_cb(koe_plugin_registry_t *reg,
                              koe_plugin_send_fn fn, void *ctx)
{
    (void)reg;
    s_send_fn  = fn;
    s_send_ctx = ctx;
}

void koe_plugin_set_log_cb(koe_plugin_registry_t *reg,
                             koe_plugin_log_fn fn, void *ctx)
{
    (void)reg;
    s_log_fn  = fn;
    s_log_ctx = ctx;
}

/* ---------------------------------------------------------------------- */
/* Stats                                                                     */
/* ---------------------------------------------------------------------- */

void koe_plugin_stats(const koe_plugin_t *plugin, char *buf, int buf_len)
{
    snprintf(buf, (size_t)buf_len,
             "[%s v%s] events=%llu suppressed=%llu errors=%llu loaded=%s",
             plugin->desc.name, plugin->desc.version,
             (unsigned long long)plugin->events_processed,
             (unsigned long long)plugin->events_suppressed,
             (unsigned long long)plugin->errors,
             plugin->loaded ? "yes" : "no");
}
