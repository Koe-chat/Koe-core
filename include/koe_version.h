/*
 * koe_version.h - Protocol version definition and compatibility negotiation.
 *
 * Compatibility rule:
 *   Two peers are compatible if they are within one major version of each
 *   other.  Examples:
 *
 *     v0.9  <->  v1.0   OK  (adjacent majors)
 *     v0.9  <->  v1.1   FAIL (adjacent majors but responder has moved on)
 *     v1.0  <->  v1.9   OK  (same major)
 *     v1.9  <->  v2.0   OK  (adjacent majors)
 *     v1.9  <->  v2.1   FAIL
 *
 * The version is embedded in every packet header and in the HELLO handshake
 * payload so peers can reject incompatible connections immediately.
 *
 * This header is intentionally bindgen-friendly:
 *   - No anonymous structs or unions
 *   - All function-like macros avoided where a typed constant works
 *   - Every exported symbol has an explicit C type
 */

#ifndef KOE_VERSION_H
#define KOE_VERSION_H

#include <stdint.h>

/* Library version (follows semver). */
#define KOE_VERSION_MAJOR  0
#define KOE_VERSION_MINOR  1
#define KOE_VERSION_PATCH  0

/* Wire-protocol version (may differ from the library version). */
#define KOE_PROTO_MAJOR    0
#define KOE_PROTO_MINOR    1

/* Packed into two bytes in the packet header and HELLO payload. */
#define KOE_PROTO_WIRE  ((uint16_t)(((KOE_PROTO_MAJOR) << 8) | (KOE_PROTO_MINOR)))

/* Human-readable strings. */
#define KOE_VERSION_STRING  "0.1.0"
#define KOE_PROTO_STRING    "0.1"

/* ---------------------------------------------------------------------- */

/*
 * koe_version_t - Version carried on the wire.
 *
 * Packed into the first two bytes of every HELLO payload.
 */
typedef struct {
    uint8_t major;
    uint8_t minor;
} koe_version_t;

/*
 * koe_version_local - Return the version this build implements.
 */
koe_version_t koe_version_local(void);

/*
 * koe_version_compatible - Check whether two versions can communicate.
 *
 * Returns 1 if compatible, 0 if not.
 *
 * Rule: compatible iff
 *   (a.major == b.major) OR
 *   (|a.major - b.major| == 1 AND the lower version's minor is the
 *    highest of its major series, i.e. the peer should accept the
 *    next major's .0 release).
 *
 * In practice for v0.x clients this means: compatible with v1.0 only.
 * For v1.x clients: compatible with v0.* and v2.0 only.
 */
int koe_version_compatible(koe_version_t a, koe_version_t b);

/*
 * koe_version_negotiate - Pick the highest mutually compatible version.
 *
 * out: set to the negotiated version on success.
 * Returns 0 on success, -1 if incompatible.
 */
int koe_version_negotiate(koe_version_t local,
                           koe_version_t remote,
                           koe_version_t *out);

/*
 * koe_version_string - Format a version as "MAJOR.MINOR" into buf.
 *
 * buf must be at least 8 bytes.
 */
void koe_version_string(koe_version_t v, char *buf, int buf_len);

#endif /* KOE_VERSION_H */
