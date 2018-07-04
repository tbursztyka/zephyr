/** @file
 * @brief UDP packet helpers.
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_NET_DEBUG_UDP)
#define SYS_LOG_DOMAIN "net/udp"
#define NET_LOG_ENABLED 1
#endif

#include "net_private.h"
#include "udp_internal.h"

#define PKT_WAIT_TIME K_SECONDS(1)

int net_udp_create(struct net_pkt *pkt, u16_t src_port, u16_t dst_port)
{
	size_t length = net_pkt_get_len(pkt) -
		net_pkt_ip_hdr_len(pkt) -
		net_pkt_ipv6_ext_len(pkt) +
		NET_UDPH_LEN;

	NET_DBG("UDP Header - total len: %zu ", length);

	if (net_pkt_write_be16(pkt, src_port) ||
	    net_pkt_write_be16(pkt, dst_port) ||
	    net_pkt_write_be16(pkt, length) ||
	    net_pkt_write_be16(pkt, 0)) {
		return -ENOBUFS;
	}

	return 0;
}

int net_udp_set_chksum(struct net_pkt *pkt)
{
	struct net_udp_hdr *hdr;
	u16_t chksum = 0;

	net_pkt_set_overwrite(pkt, true);

	net_pkt_iter_init_to_headers(pkt);

	if (net_pkt_skip(pkt, net_pkt_ip_hdr_len(pkt) +
			 net_pkt_ipv6_ext_len(pkt))) {
		NET_ERR("Could not skip to checksum area");
		return -ENOBUFS;
	}

	hdr = net_pkt_iter_get_pos(pkt);
	if (net_udp_header_fits(pkt, hdr)) {
		hdr->chksum = 0;
		hdr->chksum = net_calc_chksum_udp(pkt);

		NET_DBG("Wrote checksum 0x%04x", ntohs(hdr->chksum));

		return 0;
	}

	if (net_pkt_skip(pkt, 2 + 2 + 2 /* src + dst + len */) ||
	    net_pkt_memset(pkt, 0, sizeof(chksum))) {
		NET_ERR("Could not memset checksum area");
		return -ENOBUFS;
	}

	chksum = net_calc_chksum_udp(pkt);

	net_pkt_iter_init(pkt);
	net_pkt_skip(pkt, net_pkt_ip_hdr_len(pkt) +
		     net_pkt_ipv6_ext_len(pkt) +
		     2 + 2 + 2 /* src + dst + len */);

	NET_DBG("Wrote checksum 0x%04x", ntohs(chksum));

	return net_pkt_write(pkt, &chksum, sizeof(chksum));
}

u16_t net_udp_get_chksum(struct net_pkt *pkt)
{
	struct net_udp_hdr *hdr;
	u16_t chksum;

	net_pkt_iter_init(pkt);

	if (net_pkt_skip(pkt, net_pkt_ip_hdr_len(pkt) +
			 net_pkt_ipv6_ext_len(pkt))) {
		return 0;
	}

	hdr = net_pkt_iter_get_pos(pkt);
	if (net_udp_header_fits(pkt, hdr)) {
		return hdr->chksum;
	}

	if (net_pkt_skip(pkt, 2 + 2 + 2 /* src + dst + len */) ||
	    net_pkt_read(pkt, &chksum, sizeof(chksum))) {
		return 0;
	}

	return chksum;
}

struct net_udp_hdr *net_udp_get_hdr(struct net_pkt *pkt,
				    struct net_udp_hdr *hdr)
{
	struct net_udp_hdr *udp_hdr;

	net_pkt_iter_init(pkt);

	if (net_pkt_skip(pkt, net_pkt_ip_hdr_len(pkt) +
			 net_pkt_ipv6_ext_len(pkt))) {
		return NULL;
	}

	udp_hdr = net_pkt_iter_get_pos(pkt);
	if (net_udp_header_fits(pkt, udp_hdr)) {
		return udp_hdr;
	}

	if (net_pkt_read(pkt, &hdr->src_port, sizeof(hdr->src_port)) ||
	    net_pkt_read(pkt, &hdr->dst_port, sizeof(hdr->dst_port)) ||
	    net_pkt_read(pkt, &hdr->len,  sizeof(hdr->len)) ||
	    net_pkt_read(pkt, &hdr->chksum, sizeof(hdr->chksum))) {
		return NULL;
	}

	return hdr;
}

struct net_udp_hdr *net_udp_set_hdr(struct net_pkt *pkt,
				    struct net_udp_hdr *hdr)
{
	if (net_udp_header_fits(pkt, hdr)) {
		return hdr;
	}

	net_pkt_iter_init(pkt);

	if (net_pkt_skip(pkt, net_pkt_ip_hdr_len(pkt) +
			 net_pkt_ipv6_ext_len(pkt)) ||
	    net_pkt_write(pkt, &hdr->src_port, sizeof(hdr->src_port)) ||
	    net_pkt_write(pkt, &hdr->dst_port, sizeof(hdr->dst_port)) ||
	    net_pkt_write(pkt, &hdr->len,  sizeof(hdr->len)) ||
	    net_pkt_write(pkt, &hdr->chksum, sizeof(hdr->chksum))) {
		return NULL;
	}

	return hdr;
}

int net_udp_register(const struct sockaddr *remote_addr,
				   const struct sockaddr *local_addr,
				   u16_t remote_port,
				   u16_t local_port,
				   net_conn_cb_t cb,
				   void *user_data,
				   struct net_conn_handle **handle)
{
	return net_conn_register(IPPROTO_UDP, remote_addr, local_addr,
				 remote_port, local_port, cb, user_data,
				 handle);
}

int net_udp_unregister(struct net_conn_handle *handle)
{
	return net_conn_unregister(handle);
}
