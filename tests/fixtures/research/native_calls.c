/* Static research fixture. main does not call any case. Never execute it.
 * The only filesystem sink is a read-only open; no XPC connection is made.
 */
#include <fcntl.h>
#include <xpc/xpc.h>

#ifndef TBM_CASE
#define TBM_CASE 0
#endif

#if TBM_CASE == 0 || TBM_CASE == 1
__attribute__((noinline)) int corpus_controlled_path(xpc_object_t request) {
    const char *path = xpc_dictionary_get_string(request, "path");
    return open(path, O_RDONLY);
}

#endif

#if TBM_CASE == 0 || TBM_CASE == 2
__attribute__((noinline)) int corpus_constant_path(xpc_object_t request) {
    (void)xpc_dictionary_get_string(request, "path");
    return open("/dev/null", O_RDONLY);
}

#endif

#if TBM_CASE == 0 || TBM_CASE == 3
__attribute__((noinline)) const char *corpus_wrapper(xpc_object_t request) {
    return xpc_dictionary_get_string(request, "path");
}

__attribute__((noinline)) int corpus_wrapper_path(xpc_object_t request) {
    return open(corpus_wrapper(request), O_RDONLY);
}

#endif

int main(void) { return 0; }
