/* umineko.h - the C ABI of Umineko, Pure-Rust implementations of everything
 *
 * Every declaration here mirrors one item of the Rust crate: a type `X` becomes the opaque
 * handle `umineko_x_t` together with the `umineko_x_*` functions that operate on it, and a
 * `Result<T, XError>` becomes a `umineko_x_error_t` return with the result written through
 * an out-parameter.
 *
 * Ownership follows one rule: whatever a `_new`, a `_clone` or an out-parameter hands over
 * is released by the caller with the matching `_free`. A pointer answered by anything else
 * is borrowed, lives no longer than the object it came from, and must not be released.
 *
 * https://github.com/nercone-dev/umineko/
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef UMINEKO_H
#define UMINEKO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Registers the providers of the current platform. Returns true when they are installed. */
bool umineko_provider_install(void);

/* TODO */

#ifdef __cplusplus
}
#endif

#endif /* UMINEKO_H */
