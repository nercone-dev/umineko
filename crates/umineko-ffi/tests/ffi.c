/* ffi.c - a smoke test for the C ABI of Umineko
 *
 * Compiled and run by CI against libumineko both as a shared and as a static library, so it
 * proves that the header is self-contained, that the library links, and that it starts up.
 *
 * https://github.com/nercone-dev/umineko/
 *
 * SPDX-License-Identifier: MIT
 */

#include <umineko.h>

int main(void)
{
    if (!umineko_provider_install()) {
        return 1;
    }
    return 0;
}
