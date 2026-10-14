/* Deterministic syscall fault injection: no root, raw socket or TUN needed. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
static ssize_t fake_write(int fd,const void *buf,size_t len);
static ssize_t fake_sendto(int fd,const void *buf,size_t len,int flags,const struct sockaddr *a,socklen_t al);
static int fake_epoll_ctl(int fd,int op,int target,struct epoll_event *ev);
#define write fake_write
#define sendto fake_sendto
#define epoll_ctl fake_epoll_ctl
#include "../src/icmptun.c"
#undef write
#undef sendto
#undef epoll_ctl
static int write_errno,send_errno,epoll_errno;
static unsigned writes,sends,mods;
static uint32_t tun_events,send_events;
static ssize_t fake_write(int fd,const void *buf,size_t len) {
    (void)fd;(void)buf;writes++;
    if(write_errno) { errno=write_errno;write_errno=0;return -1; }
    return (ssize_t)len;
}
static ssize_t fake_sendto(int fd,const void *buf,size_t len,int flags,const struct sockaddr *a,socklen_t al) {
    (void)fd;(void)buf;(void)flags;(void)a;(void)al;sends++;
    if(send_errno) { errno=send_errno;send_errno=0;return -1; }
    return (ssize_t)len;
}
static int fake_epoll_ctl(int fd,int op,int target,struct epoll_event *ev) {
    (void)fd;assert(op==EPOLL_CTL_MOD);mods++;
    if(epoll_errno) { errno=epoll_errno;epoll_errno=0;return -1; }
    if(target==tun_fd) tun_events=ev->events; else send_events=ev->events;
    return 0;
}
int main(void) {
    tun_fd=11;icmp_fd=12;epoll_fd=13;
    tun_pending=calloc(TUN_PENDING_LIMIT,sizeof(*tun_pending));
    send_queue=calloc(QUEUE_SIZE,sizeof(*send_queue));
    assert(tun_pending && send_queue);
    unsigned char p[40]={0};
    write_errno=EINTR; tun_deliver(p,sizeof(p));
    assert(writes==2 && metrics.tun_tx==1 && !tun_count);
    write_errno=EAGAIN; tun_deliver(p,sizeof(p));
    assert(tun_count==1 && tun_blocked && (tun_events&EPOLLOUT));
    tun_deliver(p,sizeof(p)); assert(tun_count==2);
    tun_drain(); assert(!tun_count && !tun_blocked && !(tun_events&EPOLLOUT));
    tun_count=IO_BATCH+1;
    for(unsigned i=0;i<TUN_PENDING_LIMIT;i++) tun_pending[i].len=40;
    tun_drain(); assert(tun_count==1 && tun_blocked);
    tun_drain(); assert(tun_count==0 && !tun_blocked);
    sq_count=TX_BATCH+1;
    for(int i=0;i<QUEUE_SIZE;i++) send_queue[i].len=40;
    send_errno=EAGAIN;send_flush();
    assert(sq_count==TX_BATCH+1 && send_blocked && (send_events&EPOLLOUT));
    send_errno=EINTR;send_flush();
    assert(sq_count==2 && send_blocked); /* EINTR also consumes fairness budget */
    tun_set_readable(0);assert(tun_read_paused);
    send_flush(); assert(!sq_count && !send_blocked && !tun_read_paused);
    unsigned before=mods;
    epoll_errno=EINTR;tun_set_readable(0);
    assert(mods==before+2 && tun_read_paused && !io_failed);
    epoll_errno=EBADF;tun_set_readable(1);
    assert(io_failed && tun_read_paused); /* no false state update */
    free(tun_pending);free(send_queue);
    puts("PASS: EINTR/EAGAIN, bounded drain, EPOLLOUT, intake resume and fatal epoll failure");
}
