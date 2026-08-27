#include <assert.h>
#include <stdio.h>

#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_timer.h>

#include "dpdktcp.h"

#define RX_RING_SIZE 64
#define TX_RING_SIZE 64
#define NUM_MBUFS 256
#define MBUF_CACHE_SIZE 128

#define ETHER_TYPE_IPv4 0x0800
#define IPPROTO_TCP 6
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

#define MAX_CONNECTIONS 64
#define MAX_TCP_PAYLOAD (1500 - sizeof(struct ipv4_hdr) - sizeof(struct tcp_hdr))

struct ipv4_hdr {
	uint8_t header_len: 4, version: 4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t chksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((packed));

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t sent_seq;
	uint32_t recv_ack;
	uint8_t data_off;
	uint8_t tcp_flags;
	uint16_t rx_win;
	uint16_t cksum;
	uint16_t tcp_urp;
} __attribute__((packed));

static struct pcb {
	enum {
		TCP_CLOSED,
		TCP_ESTABLISHED
	} state;
	uint32_t sent_seq;
	uint32_t recv_ack;
	uint32_t acked;
	struct ether_addr remote_mac;
	uint32_t remote_ip;
	uint16_t local_port;
	uint16_t remote_port;
	void *arg;
} pcbs[MAX_CONNECTIONS];

static int local_tcp_port_start;
static int pcb_idx;
static struct rte_mempool *mbuf_pool;
static struct ether_addr local_mac;
static uint32_t local_ip;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.hw_ip_checksum = 1,
		.max_rx_pkt_len = ETHER_MAX_LEN
	}
};

static void port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	int ret;

	assert(port < rte_eth_dev_count());

	ret = rte_eth_dev_configure(port, 1, 1, &port_conf_default);
	assert(ret == 0);

	ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
	assert(ret >= 0);

	ret = rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
	assert(ret >= 0);

	ret = rte_eth_dev_start(port);
	assert(ret >= 0);

	rte_eth_promiscuous_enable(port);
}

static uint16_t ipv4_cksum(struct ipv4_hdr *ipv4_hdr)
{
	uint32_t *data32 = (uint32_t *) ipv4_hdr;
	uint64_t sum = 0;

	_Static_assert(sizeof(struct ipv4_hdr) == 20, "");

	sum += data32[0];
	sum += data32[1];
	sum += data32[2];
	sum += data32[3];
	sum += data32[4];
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return ~sum;
}

static uint16_t tcp_cksum(struct ipv4_hdr *ipv4_hdr, struct tcp_hdr *tcp_hdr, const char *payload, size_t len)
{
	uint32_t *data32 = (uint32_t *) tcp_hdr;
	uint16_t *data16;
	uint8_t *data8;
	uint64_t sum = 0;
	size_t data_off;
	int i;

	data_off = (tcp_hdr->data_off >> 4);
	for (i = 0; i < data_off; i++)
		sum += data32[i];
	sum += ipv4_hdr->src_addr;
	sum += ipv4_hdr->dst_addr;
	sum += ipv4_hdr->proto << 8;
	sum += __builtin_bswap16(data_off * 4 + len);
	data32 = (uint32_t *) payload;
	while (len >= 4) {
		sum += *data32;
		data32++;
		len -= 4;
	}
	data16 = (uint16_t *) data32;
	while (len >= 2) {
		sum += *data16;
		data16++;
		len -= 2;
	}
	if (len) {
		data8 = (uint8_t *) data16;
		sum += *data8;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	return ~sum;
}

static struct rte_mbuf *tx_prep(const struct pcb *pcb, size_t payload_len)
{
	struct ether_hdr *ether_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct rte_mbuf *mbuf;

	mbuf = rte_pktmbuf_alloc(mbuf_pool);
	mbuf->pkt_len = mbuf->data_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + payload_len;
	// TODO: FIXME checksum offload
	// mbuf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	// mbuf->l2_len = sizeof(struct ether_hdr);
	// mbuf->l3_len = sizeof(struct ipv4_hdr);
	ether_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(ether_hdr + 1);

	memcpy(&ether_hdr->d_addr, &pcb->remote_mac, sizeof(ether_hdr->d_addr));
	memcpy(&ether_hdr->s_addr, &local_mac, sizeof(ether_hdr->s_addr));
	ether_hdr->ether_type = __builtin_bswap16(ETHER_TYPE_IPv4);

	ipv4_hdr->header_len = 0x5;
	ipv4_hdr->version = 0x4;
	ipv4_hdr->tos = 0x0;
	ipv4_hdr->len = __builtin_bswap16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + payload_len);
	ipv4_hdr->id = 0;
	ipv4_hdr->off = 0x40;
	ipv4_hdr->ttl = 0x40;
	ipv4_hdr->proto = IPPROTO_TCP;
	ipv4_hdr->chksum = 0;
	ipv4_hdr->src_addr = local_ip;
	ipv4_hdr->dst_addr = pcb->remote_ip;

	ipv4_hdr->chksum = ipv4_cksum(ipv4_hdr);

	return mbuf;
}

static void tx_tcp_flags(struct pcb *pcb, uint8_t tcp_flags)
{
	struct ether_hdr *ether_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct tcp_hdr *tcp_hdr;
	uint32_t *tcp_options;
	struct rte_mbuf *mbufs[0];
	uint16_t count;

	mbufs[0] = tx_prep(pcb, tcp_flags == TCP_SYN ? 8 : 0);
	ether_hdr = rte_pktmbuf_mtod(mbufs[0], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(ether_hdr + 1);
	tcp_hdr = (struct tcp_hdr *)(ipv4_hdr + 1);
	tcp_options = (uint32_t *)(tcp_hdr + 1);

	tcp_hdr->src_port = pcb->local_port;
	tcp_hdr->dst_port = pcb->remote_port;
	tcp_hdr->sent_seq = __builtin_bswap32(pcb->sent_seq);
	tcp_hdr->recv_ack = __builtin_bswap32(pcb->recv_ack);
	tcp_hdr->data_off = 5 << 4;
	tcp_hdr->tcp_flags = tcp_flags;
	tcp_hdr->rx_win = 0x40;
	tcp_hdr->cksum = 0;
	tcp_hdr->tcp_urp = 0;
	if (tcp_flags == TCP_SYN) {
		tcp_hdr->data_off = 7 << 4;
		tcp_options[0] = __builtin_bswap32(0x020405B4); // mss
		tcp_options[1] = __builtin_bswap32(0x03030a00); // window scale
	}

	tcp_hdr->cksum = tcp_cksum(ipv4_hdr, tcp_hdr, NULL, 0);

	count = rte_eth_tx_burst(0, 0, mbufs, 1);
	assert(count == 1);

	pcb->acked = pcb->recv_ack;
}

static void tcp_input(struct rte_mbuf *mbuf)
{
	struct ether_hdr *ether_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct tcp_hdr *tcp_hdr;
	struct pcb *pcb;
	size_t data_off;
	size_t payload_len;
	char *payload;

	ether_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(ether_hdr + 1);
	tcp_hdr = (struct tcp_hdr *)(ipv4_hdr + 1);

	if (tcp_hdr->dst_port < local_tcp_port_start || tcp_hdr->dst_port >= local_tcp_port_start + MAX_CONNECTIONS)
		return;

	pcb = &pcbs[tcp_hdr->dst_port - local_tcp_port_start];
	data_off = (tcp_hdr->data_off >> 4) * 4;
	payload_len = __builtin_bswap16(ipv4_hdr->len) - sizeof(struct ipv4_hdr) - data_off;
	payload = (char *) tcp_hdr + data_off;

	if (tcp_hdr->tcp_flags == (TCP_SYN | TCP_ACK)) {
		pcb->recv_ack = __builtin_bswap32(tcp_hdr->sent_seq) + 1;
		tx_tcp_flags(pcb, TCP_ACK);
		on_tcp_connected(pcb->arg);
	} else if (tcp_hdr->tcp_flags & TCP_RST) {
		assert(0);
	} else if (__builtin_bswap16(ipv4_hdr->len) > sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr)) {
		assert(__builtin_bswap32(tcp_hdr->sent_seq) == pcb->recv_ack);
		pcb->recv_ack = __builtin_bswap32(tcp_hdr->sent_seq) + payload_len;
		on_tcp_recv(pcb->arg, payload, payload_len);
		if (pcb->acked != pcb->recv_ack)
			tx_tcp_flags(pcb, TCP_ACK);
	}

	// printf("tcp-in from %08x:%d to %08x:%d seq %u ack %u flags 0x%x len %lu\n",
		// __builtin_bswap32(ipv4_hdr->src_addr),
		// __builtin_bswap16(tcp_hdr->src_port),
		// __builtin_bswap32(ipv4_hdr->dst_addr),
		// __builtin_bswap16(tcp_hdr->dst_port),
		// __builtin_bswap32(tcp_hdr->sent_seq),
		// __builtin_bswap32(tcp_hdr->recv_ack),
		// tcp_hdr->tcp_flags,
		// payload_len);
}

static void eth_input(struct rte_mbuf *mbuf)
{
	struct ether_hdr *ether_hdr;
	struct ipv4_hdr *ipv4_hdr;

	ether_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(ether_hdr + 1);

	if (ether_hdr->ether_type != __builtin_bswap16(ETHER_TYPE_IPv4))
		return;

	if (ipv4_hdr->proto != IPPROTO_TCP)
		return;

	tcp_input(mbuf);

	rte_pktmbuf_free(mbuf);
}

void dpdk_init(int core, const struct ether_addr *mac, uint32_t ip)
{
	int ret;
	char corestr[8];
	char *argv[] = { "./a.out", "-l", corestr, "--log-level", "4", "-m", "512" };

	sprintf(corestr, "%d", core);

	ret = rte_eal_init(sizeof(argv) / sizeof(argv[0]), argv);
	assert(ret >= 0);

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	assert(mbuf_pool);

	port_init(0, mbuf_pool);

	rte_timer_subsystem_init();

	local_mac = *mac;
	local_ip = ip;
}

void dpdk_loop(void)
{
	struct rte_mbuf *mbufs[1];

	rte_timer_manage();

	if (!rte_eth_rx_burst(0, 0, mbufs, 1))
		return;

	eth_input(mbufs[0]);
}

void tcp_init(void)
{
	srand(time(NULL));
	local_tcp_port_start = rand() & 0xffff;
}

struct pcb *tcp_create(void *arg)
{
	struct pcb *pcb;

	assert(pcb_idx < MAX_CONNECTIONS);

	pcb = &pcbs[pcb_idx];
	pcb->arg = arg;
	pcb->local_port = local_tcp_port_start + pcb_idx;

	pcb_idx++;

	return pcb;
}

void tcp_connect(struct pcb *pcb, const struct ether_addr *mac, uint32_t ip, uint16_t port)
{
	pcb->remote_mac = *mac;
	pcb->remote_ip = ip;
	pcb->remote_port = __builtin_bswap16(port);

	tx_tcp_flags(pcb, TCP_SYN);

	pcb->sent_seq++;
}

static void __tcp_send(struct pcb *pcb, const void *data, size_t len)
{
	struct ether_hdr *ether_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct tcp_hdr *tcp_hdr;
	char *payload;
	struct rte_mbuf *mbufs[1];
	uint16_t count;

	assert(len <= MAX_TCP_PAYLOAD);

	mbufs[0] = tx_prep(pcb, len);
	ether_hdr = rte_pktmbuf_mtod(mbufs[0], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(ether_hdr + 1);
	tcp_hdr = (struct tcp_hdr *)(ipv4_hdr + 1);
	payload = (char *)(tcp_hdr + 1);

	// TODO: zero copy send
	memcpy(payload, data, len);

	tcp_hdr->src_port = pcb->local_port;
	tcp_hdr->dst_port = pcb->remote_port;
	tcp_hdr->sent_seq = __builtin_bswap32(pcb->sent_seq);
	tcp_hdr->recv_ack = __builtin_bswap32(pcb->recv_ack);
	tcp_hdr->data_off = 5 << 4;
	tcp_hdr->tcp_flags = TCP_PSH | TCP_ACK;
	tcp_hdr->rx_win = 0x40;
	tcp_hdr->cksum = 0;
	tcp_hdr->tcp_urp = 0;

	tcp_hdr->cksum = tcp_cksum(ipv4_hdr, tcp_hdr, payload, len);

	// TODO: move to tcp_send
	count = rte_eth_tx_burst(0, 0, mbufs, 1);
	assert(count == 1);

	pcb->sent_seq += len;
	pcb->acked = pcb->recv_ack;
}

void tcp_send(struct pcb *pcb, const void *data, size_t len)
{
	const char *cdata = (const char *) data;

	while (len > MAX_TCP_PAYLOAD) {
		__tcp_send(pcb, cdata, MAX_TCP_PAYLOAD);
		cdata += MAX_TCP_PAYLOAD;
		len -= MAX_TCP_PAYLOAD;
	}

	if (len)
		__tcp_send(pcb, cdata, len);
}
