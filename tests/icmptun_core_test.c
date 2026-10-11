/* Offline, unprivileged Direct ICMP regression tests.
 * Build with -fsanitize=address,undefined; never opens a raw socket. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/icmptun.c"

static void make_inner(unsigned char *ip, unsigned sport) {
    memset(ip, 0, 40);
    ip[0] = 0x45; /* IPv4 IHL = 5 */
    ip[2] = 0; ip[3] = 40; /* total length */
    ip[9] = IPPROTO_TCP;
    ip[12] = 10; ip[13] = 77; ip[14] = 79; ip[15] = 1;
    ip[16] = 10; ip[17] = 77; ip[18] = 79; ip[19] = 2;
    ip[20] = (unsigned char)(sport >> 8);
    ip[21] = (unsigned char)sport;
    ip[22] = 0x01; ip[23] = 0xbb;
}
int main(void) {
    assert(flow_init(1024) == 0);
    assert(flow_init(1000) < 0);
    assert(flow_init(65537) < 0);
    tun_pending = calloc(TUN_PENDING_LIMIT, sizeof(*tun_pending));
    assert(tun_pending);
    tun_fd = open("/dev/null", O_WRONLY);
    assert(tun_fd >= 0);
    loop_clock_ms = (uint32_t)now_ms();

    unsigned char inner[40], other[40];
    make_inner(inner, 9090);
    make_inner(other, 9091);
    flow_key_t a, b;
    assert(flow_key_from_inner(inner, 40, &a) == 1);
    assert(flow_key_from_inner(other, 40, &b) == 1);
    assert(!flow_key_eq(&a, &b));
    assert(flow_key_hash(&a) != flow_key_hash(&b));
    assert(flow_key_from_inner(inner, 8, &a) == 0);
    assert(flow_key_from_inner(inner, 40, &a) == 1);
    uint32_t h = flow_key_hash(&a);
    flow_entry_t *f = flow_get_or_create(&a, h, FLOW_ROLE_RX);
    assert(f == flow_table_lookup(&a, h));
    assert(metrics.active_flows == 1);

    /* Reorder 0, 2, 1: no loss or change in per-flow sequence semantics. */
    flow_rx_packet(f, inner, 40, 0);
    flow_rx_packet(f, inner, 40, 2);
    assert(metrics.tun_tx == 1 && f->pending == 1);
    flow_rx_packet(f, inner, 40, 2);  /* duplicate consumes no extra slot */
    assert(f->pending == 1);
    flow_rx_packet(f, inner, 40, 1);
    assert(metrics.tun_tx == 3);
    assert(f->rx_next_seq == 3 && f->pending == 0);

    /* Populate a saturated heap with expired/stale accelerators. The next
       real reorder deadline must still be scheduled, then must fire. */
    timer_heap_size = timer_heap_capacity;
    flow_rx_packet(f, inner, 40, 5);
    assert(f->pending == 1 && f->timer_deadline != 0);
    assert(timer_heap_size > 0 && timer_heap_size < timer_heap_capacity);
    timer_heap_process_expired(loop_clock_ms + REORDER_TIMEOUT_MS + 10);
    assert(f->pending == 0 && f->rx_next_seq == 6);
    assert(metrics.reorder_timeouts >= 1);

    /* Far-ahead resync must not retain outstanding buffered packets. */
    flow_rx_packet(f, inner, 40, 8);
    assert(f->pending == 1);
    flow_rx_packet(f, inner, 40, 600);
    assert(f->pending == 0);
    assert(f->rx_next_seq == 601);

    mtu = 1320;
    local_ident = 0x4d54;
    remote_ident = local_ident; /* local offline round trip only */
    peer_ip.s_addr = inet_addr("192.0.2.9");
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr = peer_ip;
    out_pkt_t out;
    assert(encapsulate(inner, 40, 77, &out) == 0);
    assert(out.len == 64); /* Echo header 8 + minimum padded payload 56 */
    unsigned char raw[MAX_PKT] = {0}, decoded[MAX_INNER];
    struct iphdr *outer = (struct iphdr*)raw;
    outer->version = 4; outer->ihl = 5; outer->protocol = IPPROTO_ICMP;
    memcpy(raw + 20, out.data, (size_t)out.len);
    struct sockaddr_in from = {.sin_family = AF_INET, .sin_addr = peer_ip};
    int decoded_len = 0; uint16_t seq = 0;
    assert(decapsulate(raw, (int)out.len + 20, decoded, &decoded_len, &seq, &from) == 0);
    assert(decoded_len == 40 && seq == 77 && memcmp(decoded, inner, 40) == 0);
    from.sin_addr.s_addr = inet_addr("192.0.2.10");
    assert(decapsulate(raw, (int)out.len + 20, decoded, &decoded_len, &seq, &from) != 0);
    from.sin_addr = peer_ip;
    raw[20 + 8 + 3] ^= 0x10; /* tamper with inner payload; wrong ICMP checksum */
    assert(decapsulate(raw, (int)out.len + 20, decoded, &decoded_len, &seq, &from) != 0);
    raw[20 + 8 + 3] ^= 0x10;

    /* Trigger an in-bucket four-way collision and eviction, without any IP traffic. */
    flow_key_t candidates[5];
    unsigned found = 0;
    for (unsigned i = 1; i < 65536 && found < 5; ++i) {
        flow_key_t key = a;
        key.sport = (uint16_t)i;
        if ((flow_key_hash(&key) & (flow_bucket_count - 1)) == 0)
            candidates[found++] = key;
    }
    assert(found == 5);
    for (unsigned i = 0; i < 5; ++i) {
        uint32_t ph = flow_key_hash(&candidates[i]);
        (void)flow_get_or_create(&candidates[i], ph, FLOW_ROLE_TX);
    }
    assert(metrics.flow_evictions > 0);
    assert(metrics.active_flows <= 1024);

    for (unsigned i = 0; i < flow_bucket_count; ++i)
        for (unsigned j = 0; j < FLOW_TABLE_WAYS; ++j)
            flow_evict(&flow_table[i].slots[j]);
    free(flow_table);
    free(timer_heap);
    free(tun_pending);
    close(tun_fd);
    puts("PASS: flow hashing, lookup, eviction, pending counter, timer exhaustion, wire framing and source checks");
    return 0;
}
