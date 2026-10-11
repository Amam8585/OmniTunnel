/* Offline RFC 6455 handshake tests; no network privileges needed.
 * Build: gcc -Wall -Wextra -g -fsanitize=address,undefined
 *   tests/ws_handshake_test.c src/monocypher.c -pthread -o /tmp/ws-test */
#define _GNU_SOURCE
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "../src/obscws.c"

int main(void) {
    char accept[29];
    assert(ws_accept("dGhlIHNhbXBsZSBub25jZQ==", accept) == 0);
    assert(strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
    assert(ws_accept("not-24-bytes", accept) != 0);
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    const char *request =
        "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";
    assert(write(fd[0], request, strlen(request)) == (ssize_t)strlen(request));
    assert(ws_server_handshake(fd[1]) == 0);
    char response[512] = {0};
    assert(read(fd[0], response, sizeof(response)-1) > 0);
    assert(strstr(response, "HTTP/1.1 101 Switching Protocols") != NULL);
    assert(strstr(response, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != NULL);
    close(fd[0]); close(fd[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    const char *bad = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Version: 13\r\n\r\n";
    assert(write(fd[0],bad,strlen(bad)) == (ssize_t)strlen(bad));
    assert(ws_server_handshake(fd[1]) != 0);
    close(fd[0]); close(fd[1]);
    puts("PASS: RFC6455 accept digest/vector, full server upgrade and missing-key rejection");
    return 0;
}
