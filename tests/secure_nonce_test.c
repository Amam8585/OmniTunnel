/* Fail-closed entropy regression. Uses mocks: never accesses host entropy.
 * If the syscall and /dev/urandom both fail, a keyed Direct transport MUST
 * terminate before sending predictable AEAD nonces. */
#define _GNU_SOURCE
#include <sys/random.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

static ssize_t broken_getrandom(void *buf, size_t len, unsigned flags) {
    (void)buf; (void)len; (void)flags;
    errno=EIO; return -1;
}
static int broken_open(const char *path, int flags, ...) {
    (void)path; (void)flags;
    errno=EACCES; return -1;
}
#define getrandom broken_getrandom
#define open broken_open
#include "../src/tcrypto.h"
#undef getrandom
#undef open

int main(void) {
    pid_t pid=fork();
    assert(pid>=0);
    if(pid==0) {
        unsigned char nonce[NONCE_LEN];
        ts_random(nonce,sizeof(nonce));
        _exit(0); /* forbidden: deterministic or uninitialized output */
    }
    int status=0;
    assert(waitpid(pid,&status,0)==pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==70);
    puts("PASS: failed kernel entropy sources terminate before nonce generation");
    return 0;
}
