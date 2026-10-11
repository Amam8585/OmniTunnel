/* Isolated microbench: flow hash/lookup/eviction and theoretical heap size.
 * Does NOT measure tunnel goodput, tail latency or network packet loss.
 * gcc -O2 -Wall -Wextra tests/icmptun_microbench.c -o /tmp/icmp-bench
 */
#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/icmptun.c"

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000000000ULL+(uint64_t)ts.tv_nsec;
}
int main(void) {
    static const unsigned cases[]={1024,4096,8192,16384,32768,65536};
    for (unsigned k=0;k<sizeof(cases)/sizeof(cases[0]);k++) {
        unsigned size=cases[k];
        assert(flow_init(size)==0);
        memset(&metrics,0,sizeof(metrics));
        loop_clock_ms=now_ms();
        flow_key_t key={0};
        key.src_ip=0x0a000001;key.dst_ip=0x0a000002;key.proto=IPPROTO_TCP;
        const int count=120000;
        uint64_t start=monotonic_ns();
        for (int i=0;i<count;i++) {
            key.sport=(uint16_t)(10000+(i%40000));
            key.dport=(uint16_t)(3000+i%17);
            uint32_t hash=flow_key_hash(&key);
            flow_entry_t *entry=flow_get_or_create(&key,hash,FLOW_ROLE_RX);
            assert(entry && entry->valid);
        }
        uint64_t elapsed=monotonic_ns()-start;
        printf("MICROBENCH ONLY slots=%u table_MiB=%.2f timer_MiB=%.2f ns_per_insert_or_lookup=%.1f active=%"PRIu64" evicted=%"PRIu64" contention=%"PRIu64" avg_probes=%.2f\n",
            size,(double)(flow_bucket_count*sizeof(*flow_table))/(1024*1024),
            (double)((size_t)timer_heap_capacity*sizeof(*timer_heap))/(1024*1024),
            (double)elapsed/count,metrics.active_flows,metrics.flow_evictions,
            metrics.flow_collisions,metrics.flow_lookup_calls?
            (double)metrics.flow_lookup_probes/metrics.flow_lookup_calls:0.0);
        for (unsigned i=0;i<flow_bucket_count;i++)
            for (int j=0;j<FLOW_TABLE_WAYS;j++) flow_evict(&flow_table[i].slots[j]);
        free(flow_table); free(timer_heap);
        flow_table=NULL;timer_heap=NULL;timer_heap_size=0;
    }
    return 0;
}
