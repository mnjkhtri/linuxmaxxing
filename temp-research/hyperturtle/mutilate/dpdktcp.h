#pragma once

#define IP4(a, b, c, d) (a|(b<<8)|(c<<16)|(d<<24))

#ifdef __cplusplus
extern "C" {
#endif

void dpdk_init(int core, const struct ether_addr *mac, uint32_t ip);
void dpdk_loop(void);

void tcp_init(void);
struct pcb *tcp_create(void *arg);
void tcp_connect(struct pcb *pcb, const struct ether_addr *mac, uint32_t ip, uint16_t port);
void tcp_send(struct pcb *pcb, const void *data, size_t len);
void on_tcp_connected(void *arg);
void on_tcp_recv(void *arg, char *data, size_t len);

#ifdef __cplusplus
}
#endif
