/** @file
 @brief UDP data handler

 This is not to be included by the application and is only used by
 core IP stack.
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __UDP_INTERNAL_H
#define __UDP_INTERNAL_H

#include <zephyr/types.h>

#include <net/net_core.h>
#include <net/net_ip.h>
#include <net/net_pkt.h>
#include <net/net_context.h>

#include "connection.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_NET_UDP)

/**
 * @brief Write UDP packet into net_pkt
 *
 * @param pkt Network packet
 * @param src_port Source port in network byte order.
 * @param dst_port Destination port in network byte order.
 *
 * @return 0 on success, negative errno otherwise.
 */
int net_udp_create(struct net_pkt *pkt, u16_t src_port, u16_t dst_port);

/**
 * @brief Set UDP checksum in network packet.
 *
 * @param pkt Network packet
 *
 * @return 0 on success, negative errno otherwise.
 */
int net_udp_set_chksum(struct net_pkt *pkt);

/**
 * @brief Get UDP checksum from network packet.
 *
 * @param pkt Network packet
 *
 * @return Return the checksum in host byte order.
 */
u16_t net_udp_get_chksum(struct net_pkt *pkt);


#else
#define net_udp_create(...) 0
#define net_udp_set_chksum(...) NULL
#define net_udp_get_chksum(...) (0)
>>>>>>> 475e3cbf7... WIP
#endif /* CONFIG_NET_UDP */

/**
 * @brief Register a callback to be called when UDP packet
 * is received corresponding to received packet.
 *
 * @param remote_addr Remote address of the connection end point.
 * @param local_addr Local address of the connection end point.
 * @param remote_port Remote port of the connection end point.
 * @param local_port Local port of the connection end point.
 * @param cb Callback to be called
 * @param user_data User data supplied by caller.
 * @param handle UDP handle that can be used when unregistering
 *
 * @return Return 0 if the registration succeed, <0 otherwise.
 */
int net_udp_register(const struct sockaddr *remote_addr,
		     const struct sockaddr *local_addr,
		     u16_t remote_port,
		     u16_t local_port,
		     net_conn_cb_t cb,
		     void *user_data,
		     struct net_conn_handle **handle);

/**
 * @brief Unregister UDP handler.
 *
 * @param handle Handle from registering.
 *
 * @return Return 0 if the unregistration succeed, <0 otherwise.
 */
int net_udp_unregister(struct net_conn_handle *handle);

#ifdef __cplusplus
}
#endif

#endif /* __UDP_INTERNAL_H */
