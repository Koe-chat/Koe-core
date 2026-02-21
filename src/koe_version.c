/*
 * koe_version.c - Protocol version negotiation.
 */

#include "koe_version.h"
#include <stdio.h>
#include <string.h>

koe_version_t koe_version_local(void)
{
    koe_version_t v = { KOE_PROTO_MAJOR, KOE_PROTO_MINOR };
    return v;
}

/*
 * Compatibility rule:
 *   v0.9 <-> v1.0  OK  (adjacent majors, lower is last of its series)
 *   v0.9 <-> v1.1  FAIL
 *   v1.x <-> v1.y  OK  (same major)
 *   v1.9 <-> v2.0  OK
 *   v1.9 <-> v2.1  FAIL
 *
 * Implementation: two versions are compatible if:
 *   1. Same major, OR
 *   2. Major differs by exactly 1 AND the higher version's minor == 0
 *      (meaning the higher is the very first release of a new major,
 *      which is defined to overlap with all of the previous major).
 */
int koe_version_compatible(koe_version_t a, koe_version_t b)
{
    if (a.major == b.major)
        return 1;

    int diff = (int)a.major - (int)b.major;
    if (diff < 0) diff = -diff;
    if (diff != 1)
        return 0;

    /* Adjacent majors: only compatible if the higher version is x.0. */
    if (a.major > b.major)
        return a.minor == 0 ? 1 : 0;
    else
        return b.minor == 0 ? 1 : 0;
}

int koe_version_negotiate(koe_version_t local,
                           koe_version_t remote,
                           koe_version_t *out)
{
    if (!koe_version_compatible(local, remote))
        return -1;

    /* Use whichever is lower (more conservative). */
    if (local.major < remote.major ||
        (local.major == remote.major && local.minor <= remote.minor)) {
        *out = local;
    } else {
        *out = remote;
    }
    return 0;
}

void koe_version_string(koe_version_t v, char *buf, int buf_len)
{
    snprintf(buf, (size_t)buf_len, "%u.%u", v.major, v.minor);
}
