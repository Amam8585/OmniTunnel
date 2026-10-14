#define _GNU_SOURCE
#include <assert.h>
#include <time.h>
#include "../src/obsctcp.c"
static _Atomic int entered;
static void *blocked_writer(void *arg) {
    int fd=*(int*)arg;
    unsigned char payload[65536]={0};
    pthread_mutex_lock(&wlock);
    entered=1;
    while (writen(fd,payload,sizeof(payload))==0) {}
    pthread_mutex_unlock(&wlock);
    return NULL;
}
static void join_bounded(pthread_t thread) {
    struct timespec end;
    assert(clock_gettime(CLOCK_REALTIME,&end)==0);
    end.tv_sec+=3;
    assert(pthread_timedjoin_np(thread,NULL,&end)==0);
}
int main(void) {
    signal(SIGPIPE,SIG_IGN);
    assert(parse_hexkey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag")<0);
    assert(parse_hexkey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")==0);
    int fd[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);
    int cap=1024;assert(setsockopt(fd[0],SOL_SOCKET,SO_SNDBUF,&cap,sizeof(cap))==0);
    conn_fd=fd[0];
    pthread_t writer;
    assert(pthread_create(&writer,NULL,blocked_writer,&fd[0])==0);
    while (!entered) usleep(1000);
    retire_connection(fd[0]);join_bounded(writer);
    assert(conn_fd==-1);close(fd[1]);
    /* An idle TUN reader must stop even if it never receives a packet. */
    int pipefd[2];assert(pipe(pipefd)==0);tun_fd=pipefd[0];running=1;
    pthread_t reader;assert(pthread_create(&reader,NULL,uplink,NULL)==0);
    usleep(10000);running=0;join_bounded(reader);
    close(pipefd[0]);close(pipefd[1]);
    puts("PASS: blocked TCP writer retirement, idle uplink shutdown, strict hex key");
}
