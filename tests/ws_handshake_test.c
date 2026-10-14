/* Unprivileged RFC6455 handshake/frame regression, runs under ASan+UBSan. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "../src/obscws.c"

struct hs_arg { int fd; int result; };
static void *serve_upgrade(void *ptr) {
    struct hs_arg *a = ptr;
    a->result = ws_server_handshake(a->fd);
    return NULL;
}
static void *serve_wrong_accept(void *ptr) {
    struct hs_arg *a=ptr;
    char req[8193];
    a->result=ws_read_headers(a->fd, req, sizeof(req));
    static const char *bad =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
    if (a->result==0) a->result=writen(a->fd,(const unsigned char*)bad,strlen(bad));
    return NULL;
}
static void test_upgrade(void) {
    int fd[2];
    pthread_t worker;
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);
    struct hs_arg a = {fd[1], -1};
    assert(pthread_create(&worker,NULL,serve_upgrade,&a)==0);
    assert(ws_client_handshake(fd[0])==0);
    pthread_join(worker,NULL);
    assert(a.result==0);
    close(fd[0]); close(fd[1]);

    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);
    a.fd=fd[1]; a.result=-1;
    assert(pthread_create(&worker,NULL,serve_wrong_accept,&a)==0);
    unsetenv("OMNITUN_WS_ALLOW_LEGACY_ACCEPT");
    assert(ws_client_handshake(fd[0])!=0);
    pthread_join(worker,NULL);
    assert(a.result==0);
    close(fd[0]); close(fd[1]);
}
static void test_frames(void) {
    int fds[2];
    struct conn c={0};
    pthread_mutex_init(&c.sendlock,NULL);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);
    unsigned char input[200], frame[10+MAX_FRAME], out[MAX_FRAME];
    for (unsigned i=0;i<sizeof(input);i++) input[i]=(unsigned char)i;
    int n=ws_frame(frame,input,sizeof(input),1);
    is_server=1;
    assert(write(fds[0],frame,n)==n);
    assert(ws_read_frame(fds[1],&c,out,sizeof(out))==(int)sizeof(input));
    assert(memcmp(input,out,sizeof(input))==0);

    /* A client MUST mask every frame. */
    n=ws_frame(frame,input,20,0);
    assert(write(fds[0],frame,n)==n);
    assert(ws_read_frame(fds[1],&c,out,sizeof(out))<0);
    /* A rejected frame can leave unread payload bytes on a poisoned stream.
     * Real transport closes it; use a new connection for the next case. */
    close(fds[0]); close(fds[1]);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);

    /* Binary fragmentation is bounded and only delivered once complete. */
    n=ws_frame(frame,input,20,1); frame[0]=0x02;
    assert(write(fds[0],frame,n)==n);
    assert(ws_read_frame(fds[1],&c,out,sizeof(out))==0);
    n=ws_frame(frame,input+20,20,1); frame[0]=0x80;
    assert(write(fds[0],frame,n)==n);
    assert(ws_read_frame(fds[1],&c,out,sizeof(out))==40);
    assert(!memcmp(input,out,40));
    /* Continuation with no active message poisons the connection. */
    assert(write(fds[0],frame,n)==n);
    assert(ws_read_frame(fds[1],&c,out,sizeof(out))<0);
    close(fds[0]); close(fds[1]);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);

    /* A 64-bit payload-length indicator must not truncate into int. */
    const unsigned char huge[10]={0x82,0xff,0,0,0,0,0,1,0,0};
    assert(write(fds[0],huge,sizeof(huge))==(ssize_t)sizeof(huge));
    assert(ws_read_frame(fds[1],&c,out,sizeof(out))<0);
    /* A rejected frame can leave unread payload bytes on a poisoned stream.
     * Real transport closes it; use a new connection for the next case. */
    close(fds[0]); close(fds[1]);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);

    /* Ping receives a Pong of identical payload with appropriate server mask. */
    n=ws_frame(frame,input,3,1);
    frame[0]=0x89;
    assert(write(fds[0],frame,n)==n);
    assert(ws_read_frame(fds[1],&c,out,sizeof(out))==0);
    unsigned char pong[5];
    assert(readn(fds[0],pong,sizeof(pong))==0);
    assert(pong[0]==0x8a && pong[1]==3);
    assert(memcmp(pong+2,input,3)==0);
    close(fds[0]);close(fds[1]);
    pthread_mutex_destroy(&c.sendlock);
}
/* Reject malformed frames independently: a rejected frame poisons the stream
 * and MUST NOT be followed by another frame on the same connection. */
static void test_bad_frames(void) {
    static const unsigned char rsv[] = {0xc2, 0x80};
    static const unsigned char no_fin[] = {0x02, 0x80};
    static const unsigned char fragmented_ping[] = {0x09, 0x80};
    static const unsigned char unmasked_client[] = {0x82, 0x00};
    static const unsigned char bad_opcode[] = {0x83, 0x80};
    static const unsigned char nonminimal_16[] = {0x82, 0xfe, 0x00, 0x7d};
    static const unsigned char nonminimal_64[] =
        {0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 125};
    static const unsigned char oversized_64[] =
        {0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0};
    static const unsigned char oversized_control[] = {0x89, 0xfe, 0, 126};
    struct bad { const unsigned char *data; size_t len; };
    const struct bad cases[] = {
        {rsv,sizeof(rsv)}, {no_fin,sizeof(no_fin)},
        {fragmented_ping,sizeof(fragmented_ping)},
        {unmasked_client,sizeof(unmasked_client)}, {bad_opcode,sizeof(bad_opcode)},
        {nonminimal_16,sizeof(nonminimal_16)},
        {nonminimal_64,sizeof(nonminimal_64)}, {oversized_64,sizeof(oversized_64)},
        {oversized_control,sizeof(oversized_control)}
    };
    struct conn c={0};
    pthread_mutex_init(&c.sendlock,NULL);
    unsigned char out[MAX_FRAME];
    is_server=1;
    for (size_t i=0; i<sizeof(cases)/sizeof(cases[0]); ++i) {
        int fds[2];
        assert(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);
        assert(write(fds[0],cases[i].data,cases[i].len)==(ssize_t)cases[i].len);
        assert(ws_read_frame(fds[1],&c,out,sizeof(out))<0);
        close(fds[0]); close(fds[1]);
    }
    pthread_mutex_destroy(&c.sendlock);
}
/* A client replying to a server Ping MUST mask its Pong. */
static void test_client_pong_mask(void) {
    struct conn c={0};
    pthread_mutex_init(&c.sendlock,NULL);
    int fd[2];
    unsigned char frame[10+MAX_FRAME], input[]={1,2,3}, out[MAX_FRAME], pong[9];
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);
    is_server=0;
    int n=ws_frame(frame,input,3,0);
    frame[0]=0x89;
    assert(write(fd[0],frame,n)==n);
    assert(ws_read_frame(fd[1],&c,out,sizeof(out))==0);
    assert(readn(fd[0],pong,sizeof(pong))==0);
    assert(pong[0]==0x8a && pong[1]==(0x80|3));
    for (int i=0;i<3;i++) assert((pong[6+i]^pong[2+i%4])==input[i]);
    close(fd[0]); close(fd[1]);
    pthread_mutex_destroy(&c.sendlock);
}

int main(void) {
    char accept[29];
    assert(ws_accept("dGhlIHNhbXBsZSBub25jZQ==",accept)==0);
    assert(strcmp(accept,"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")==0);
    assert(ws_accept("not-24-bytes",accept)!=0);
    assert(ws_accept("dGhlIHNhbXBsZSBub25jZR==",accept)!=0); /* noncanonical padding bits */
    assert(ws_accept("dGhlIHNhbXBsZSBub25j=Q==",accept)!=0); /* embedded padding */
    assert(ws_has_token("HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, UpGrAdE\r\n\r\n","Connection","Upgrade"));
    assert(!ws_has_token("HTTP/1.1 101 Switching Protocols\r\nConnection: NotUpgrade\r\n\r\n","Connection","Upgrade"));
    assert(ws_accept("========================",accept)!=0);
    assert(ws_accept("dGhlIHNhbXBsZSBub25jZR==",accept)!=0);
    /* Every failed upgrade releases the server's reserved connection slot. */
    int fd[2];
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);
    is_server=1; conns[0].fd=-2;
    assert(write(fd[0],"BAD\r\n\r\n",7)==7);
    run_link(0,fd[1]);
    assert(conns[0].fd==-1);
    close(fd[0]);
    test_upgrade();
    test_frames();
    test_bad_frames();
    test_client_pong_mask();
    puts("PASS: RFC6455 Accept verification, client/server handshake, masked frames, fragmentation rejection, 64-bit validation and Pong");
    return 0;
}
