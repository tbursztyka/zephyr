/** @file
 * @brief Network packet buffer descriptor API
 *
 * Network data is passed between different parts of the stack via
 * net_buf struct.
 */

/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Data buffer API - used for all data to/from net */

#ifndef ZEPHYR_INCLUDE_NET_NET_PKT_H_
#define ZEPHYR_INCLUDE_NET_NET_PKT_H_

#include <zephyr/types.h>
#include <stdbool.h>

#include <net/buf.h>

#include <net/net_core.h>
#include <net/net_linkaddr.h>
#include <net/net_ip.h>
#include <net/net_if.h>
#include <net/net_context.h>
#include <net/ethernet_vlan.h>
#include <net/ptp_time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Network packet management library
 * @defgroup net_pkt Network Packet Library
 * @ingroup networking
 * @{
 */

struct net_context;

/* buffer iterator used in net_pkt */
struct net_pkt_iter {
	/** Current net_buf pointer by the iterator */
	struct net_buf *buf;
	/** Current position in the data buffer of the net_buf */
	void *pos;
};

/* Note that if you add new fields into net_pkt, remember to update
 * net_pkt_clone() function.
 */
struct net_pkt {
	/** FIFO uses first 4 bytes itself, reserve space */
	int _reserved;

	/** Internal variable that is used when packet is sent */
	struct k_work work;

	/** List of buffer(s) holding the packet */
	struct net_buf *buffer;
	struct net_buf *appdata;	/* application data starts here */

	/** Internal buffer iterator used for reading/writing */
	struct net_pkt_iter iter;

	/** Network connection context */
	struct net_context *context;

	/** Network context token that user can set. This is passed
	 * to user callback when data has been sent.
	 */
	void *token;

	/** Network interface */
	struct net_if *iface;

	/** @cond ignore */

#if defined(CONFIG_NET_ROUTING)
	struct net_if *orig_iface; /* Original network interface */
#endif

#if defined(CONFIG_NET_PKT_TIMESTAMP)
	/** Timestamp if available. */
	struct net_ptp_time timestamp;
#endif
	u8_t *next_hdr; /* where is the next header */

	u8_t *ll;       /* Link Layer Header, set by L2.
			 * (Is not useful atm, maybe for sock_raw support)
			 */
	/* Filled by layer 2 when network packet is received. */
	struct net_linkaddr lladdr_src;
	struct net_linkaddr lladdr_dst;

#if defined(CONFIG_NET_TCP)
	sys_snode_t sent_list;
#endif

	u16_t total_pkt_len;	/* Total packet length */

	u8_t ip_hdr_len;	/* pre-filled in order to avoid func call */

	/** Reference counter */
	u8_t ref;

	u8_t sent_or_eof: 1;	/* For outgoing packet: is this sent or not
				 * For incoming packet of a socket: last
				 * packet before EOF
				 * Used only if defined(CONFIG_NET_TCP)
				 */
	u8_t pkt_queued : 1;	/* For outgoing packet: is this packet queued
				 * to be sent but has not reached the driver
				 * yet. Used only if defined(CONFIG_NET_TCP)
				 */
	u8_t forwarding : 1;	/* Are we forwarding this pkt
				 * Used only if defined(CONFIG_NET_ROUTE)
				 */
	u8_t family     : 3;	/* IPv4 vs IPv6 */
	u8_t ipv4_auto_arp_msg : 1; /* Is this pkt IPv4 autoconf ARP message.
				     * Used only if
				     * defined(CONFIG_NET_IPV4_AUTO)
				     */
	u8_t overwrite  : 1;	/* Is packet content being overwritten? */

	union {
		/* IPv6 hop limit or IPv4 ttl for this network packet.
		 * The value is shared between IPv6 and IPv4.
		 */
		u8_t ipv6_hop_limit;
		u8_t ipv4_ttl;
	};

#if NET_TC_COUNT > 1
	/** Network packet priority, can be left out in which case packet
	 * is not prioritised.
	 */
	u8_t priority;
#endif

#if defined(CONFIG_NET_VLAN)
	/* VLAN TCI (Tag Control Information). This contains the Priority
	 * Code Point (PCP), Drop Eligible Indicator (DEI) and VLAN
	 * Identifier (VID, called more commonly VLAN tag). This value is
	 * kept in host byte order.
	 */
	u16_t vlan_tci;
#endif /* CONFIG_NET_VLAN */

#if defined(CONFIG_NET_IPV6)
	u16_t ipv6_ext_len;	/* length of extension headers */

	/* Where is the start of the last header before payload data
	 * in IPv6 packet. This is offset value from start of the IPv6
	 * packet. Note that this value should be updated by who ever
	 * adds IPv6 extension headers to the network packet.
	 */
	u16_t ipv6_prev_hdr_start;

#if defined(CONFIG_NET_IPV6_FRAGMENT)
	u16_t ipv6_fragment_offset;	/* Fragment offset of this packet */
	u32_t ipv6_fragment_id;	/* Fragment id */
	u16_t ipv6_frag_hdr_start;	/* Where starts the fragment header */
#endif /* CONFIG_NET_IPV6_FRAGMENT */

	u8_t ipv6_ext_opt_len; /* IPv6 ND option length */
#endif /* CONFIG_NET_IPV6 */

#if defined(CONFIG_IEEE802154)
	u8_t ieee802154_rssi; /* Received Signal Strength Indication */
	u8_t ieee802154_lqi;  /* Link Quality Indicator */
#endif
	/* @endcond */
};

/** @cond ignore */

static inline bool net_pkt_is_valid(struct net_pkt *pkt)
{
	return (pkt && pkt->buffer);
}

static inline struct k_work *net_pkt_work(struct net_pkt *pkt)
{
	return &pkt->work;
}

/* The interface real ll address */
static inline struct net_linkaddr *net_pkt_lladdr_if(struct net_pkt *pkt)
{
	return net_if_get_link_addr(pkt->iface);
}

static inline struct net_context *net_pkt_context(struct net_pkt *pkt)
{
	return pkt->context;
}

static inline void net_pkt_set_context(struct net_pkt *pkt,
				       struct net_context *ctx)
{
	pkt->context = ctx;
}

static inline void *net_pkt_token(struct net_pkt *pkt)
{
	return pkt->token;
}

static inline void net_pkt_set_token(struct net_pkt *pkt, void *token)
{
	pkt->token = token;
}

static inline struct net_if *net_pkt_iface(struct net_pkt *pkt)
{
	return pkt->iface;
}

static inline void net_pkt_set_iface(struct net_pkt *pkt, struct net_if *iface)
{
	pkt->iface = iface;

	/* If the network interface is set in pkt, then also set the type of
	 * the network address that is stored in pkt. This is done here so
	 * that the address type is properly set and is not forgotten.
	 */
	pkt->lladdr_src.type = net_if_get_link_addr(iface)->type;
	pkt->lladdr_dst.type = net_if_get_link_addr(iface)->type;
}

static inline struct net_if *net_pkt_orig_iface(struct net_pkt *pkt)
{
#if defined(CONFIG_NET_ROUTING)
	return pkt->orig_iface;
#else
	return pkt->iface;
#endif
}

static inline void net_pkt_set_orig_iface(struct net_pkt *pkt,
					  struct net_if *iface)
{
#if defined(CONFIG_NET_ROUTING)
	pkt->orig_iface = iface;
#else
	ARG_UNUSED(pkt);
	ARG_UNUSED(iface);
#endif
}

static inline u8_t net_pkt_family(struct net_pkt *pkt)
{
	return pkt->family;
}

static inline void net_pkt_set_family(struct net_pkt *pkt, u8_t family)
{
	pkt->family = family;
}

static inline u8_t net_pkt_ip_hdr_len(struct net_pkt *pkt)
{
	return pkt->ip_hdr_len;
}

static inline void net_pkt_set_ip_hdr_len(struct net_pkt *pkt, u8_t len)
{
	pkt->ip_hdr_len = len;
}

static inline u8_t *net_pkt_next_hdr(struct net_pkt *pkt)
{
	return pkt->next_hdr;
}

static inline void net_pkt_set_next_hdr(struct net_pkt *pkt, u8_t *hdr)
{
	pkt->next_hdr = hdr;
}

static inline u8_t net_pkt_sent(struct net_pkt *pkt)
{
	return pkt->sent_or_eof;
}

static inline void net_pkt_set_sent(struct net_pkt *pkt, bool sent)
{
	pkt->sent_or_eof = sent;
}

static inline u8_t net_pkt_queued(struct net_pkt *pkt)
{
	return pkt->pkt_queued;
}

static inline void net_pkt_set_queued(struct net_pkt *pkt, bool send)
{
	pkt->pkt_queued = send;
}

#if defined(CONFIG_NET_SOCKETS)
static inline u8_t net_pkt_eof(struct net_pkt *pkt)
{
	return pkt->sent_or_eof;
}

static inline void net_pkt_set_eof(struct net_pkt *pkt, bool eof)
{
	pkt->sent_or_eof = eof;
}
#endif

#if defined(CONFIG_NET_ROUTE)
static inline bool net_pkt_forwarding(struct net_pkt *pkt)
{
	return pkt->forwarding;
}

static inline void net_pkt_set_forwarding(struct net_pkt *pkt, bool forward)
{
	pkt->forwarding = forward;
}
#else
static inline bool net_pkt_forwarding(struct net_pkt *pkt)
{
	return false;
}
#endif

#if defined(CONFIG_NET_IPV4)
static inline u8_t net_pkt_ipv4_ttl(struct net_pkt *pkt)
{
	return pkt->ipv4_ttl;
}

static inline void net_pkt_set_ipv4_ttl(struct net_pkt *pkt,
					u8_t ttl)
{
	pkt->ipv4_ttl = ttl;
}
#endif

#if defined(CONFIG_NET_IPV6)
static inline u8_t net_pkt_ipv6_ext_opt_len(struct net_pkt *pkt)
{
	return pkt->ipv6_ext_opt_len;
}

static inline void net_pkt_set_ipv6_ext_opt_len(struct net_pkt *pkt,
						u8_t len)
{
	pkt->ipv6_ext_opt_len = len;
}

static inline u16_t net_pkt_ipv6_ext_len(struct net_pkt *pkt)
{
	return pkt->ipv6_ext_len;
}

static inline void net_pkt_set_ipv6_ext_len(struct net_pkt *pkt,
					    u16_t len)
{
	pkt->ipv6_ext_len = len;
}

static inline u16_t net_pkt_ipv6_hdr_prev(struct net_pkt *pkt)
{
	return pkt->ipv6_prev_hdr_start;
}

static inline void net_pkt_set_ipv6_hdr_prev(struct net_pkt *pkt,
					     u16_t offset)
{
	pkt->ipv6_prev_hdr_start = offset;
}

static inline u8_t net_pkt_ipv6_hop_limit(struct net_pkt *pkt)
{
	return pkt->ipv6_hop_limit;
}

static inline void net_pkt_set_ipv6_hop_limit(struct net_pkt *pkt,
					      u8_t hop_limit)
{
	pkt->ipv6_hop_limit = hop_limit;
}

#if defined(CONFIG_NET_IPV6_FRAGMENT)
static inline u16_t net_pkt_ipv6_fragment_start(struct net_pkt *pkt)
{
	return pkt->ipv6_frag_hdr_start;
}

static inline void net_pkt_set_ipv6_fragment_start(struct net_pkt *pkt,
						   u16_t start)
{
	pkt->ipv6_frag_hdr_start = start;
}

static inline u16_t net_pkt_ipv6_fragment_offset(struct net_pkt *pkt)
{
	return pkt->ipv6_fragment_offset;
}

static inline void net_pkt_set_ipv6_fragment_offset(struct net_pkt *pkt,
						    u16_t offset)
{
	pkt->ipv6_fragment_offset = offset;
}

static inline u32_t net_pkt_ipv6_fragment_id(struct net_pkt *pkt)
{
	return pkt->ipv6_fragment_id;
}

static inline void net_pkt_set_ipv6_fragment_id(struct net_pkt *pkt,
						u32_t id)
{
	pkt->ipv6_fragment_id = id;
}
#endif /* CONFIG_NET_IPV6_FRAGMENT */
#else /* CONFIG_NET_IPV6 */

static inline u8_t net_pkt_ipv6_ext_opt_len(struct net_pkt *pkt)
{
	ARG_UNUSED(pkt);
	return 0;
}

static inline void net_pkt_set_ipv6_ext_opt_len(struct net_pkt *pkt,
						u8_t len)
{
	ARG_UNUSED(pkt);
	ARG_UNUSED(len);
}
static inline u16_t net_pkt_ipv6_ext_len(struct net_pkt *pkt)
{
	ARG_UNUSED(pkt);
	return 0;
}

static inline void net_pkt_set_ipv6_ext_len(struct net_pkt *pkt,
					    u16_t len)
{
	ARG_UNUSED(pkt);
	ARG_UNUSED(len);
}

static inline u16_t net_pkt_ipv6_hdr_prev(struct net_pkt *pkt)
{
	ARG_UNUSED(pkt);
	return 0;
}

static inline void net_pkt_set_ipv6_hdr_prev(struct net_pkt *pkt,
					     u16_t offset)
{
	ARG_UNUSED(pkt);
	ARG_UNUSED(offset);
}

static inline u8_t net_pkt_ipv6_hop_limit(struct net_pkt *pkt)
{
	ARG_UNUSED(pkt);
	return 0;
}

static inline void net_pkt_set_ipv6_hop_limit(struct net_pkt *pkt,
					      u8_t hop_limit)
{
	ARG_UNUSED(hop_limit);
	ARG_UNUSED(pkt);
}

#endif /* CONFIG_NET_IPV6 */

#if NET_TC_COUNT > 1
static inline u8_t net_pkt_priority(struct net_pkt *pkt)
{
	return pkt->priority;
}

static inline void net_pkt_set_priority(struct net_pkt *pkt,
					u8_t priority)
{
	pkt->priority = priority;
}
#else /* NET_TC_COUNT == 1 */
static inline u8_t net_pkt_priority(struct net_pkt *pkt)
{
	return 0;
}

#define net_pkt_set_priority(...)

#endif /* NET_TC_COUNT > 1 */

#if defined(CONFIG_NET_VLAN)
static inline u16_t net_pkt_vlan_tag(struct net_pkt *pkt)
{
	return net_eth_vlan_get_vid(pkt->vlan_tci);
}

static inline void net_pkt_set_vlan_tag(struct net_pkt *pkt, u16_t tag)
{
	pkt->vlan_tci = net_eth_vlan_set_vid(pkt->vlan_tci, tag);
}

static inline u8_t net_pkt_vlan_priority(struct net_pkt *pkt)
{
	return net_eth_vlan_get_pcp(pkt->vlan_tci);
}

static inline void net_pkt_set_vlan_priority(struct net_pkt *pkt,
					     u8_t priority)
{
	pkt->vlan_tci = net_eth_vlan_set_pcp(pkt->vlan_tci, priority);
}

static inline bool net_pkt_vlan_dei(struct net_pkt *pkt)
{
	return net_eth_vlan_get_dei(pkt->vlan_tci);
}

static inline void net_pkt_set_vlan_dei(struct net_pkt *pkt, bool dei)
{
	pkt->vlan_tci = net_eth_vlan_set_dei(pkt->vlan_tci, dei);
}

static inline void net_pkt_set_vlan_tci(struct net_pkt *pkt, u16_t tci)
{
	pkt->vlan_tci = tci;
}

static inline u16_t net_pkt_vlan_tci(struct net_pkt *pkt)
{
	return pkt->vlan_tci;
}
#else
static inline u16_t net_pkt_vlan_tag(struct net_pkt *pkt)
{
	return NET_VLAN_TAG_UNSPEC;
}

static inline void net_pkt_set_vlan_tag(struct net_pkt *pkt, u16_t tag)
{
	ARG_UNUSED(pkt);
	ARG_UNUSED(tag);
}

static inline u8_t net_pkt_vlan_priority(struct net_pkt *pkt)
{
	ARG_UNUSED(pkt);
	return 0;
}

static inline bool net_pkt_vlan_dei(struct net_pkt *pkt)
{
	return false;
}

static inline void net_pkt_set_vlan_dei(struct net_pkt *pkt, bool dei)
{
	ARG_UNUSED(pkt);
	ARG_UNUSED(dei);
}

static inline u16_t net_pkt_vlan_tci(struct net_pkt *pkt)
{
	return NET_VLAN_TAG_UNSPEC; /* assumes priority is 0 */
}

static inline void net_pkt_set_vlan_tci(struct net_pkt *pkt, u16_t tci)
{
	ARG_UNUSED(pkt);
	ARG_UNUSED(tci);
}
#endif

#if defined(CONFIG_NET_PKT_TIMESTAMP)
static inline struct net_ptp_time *net_pkt_timestamp(struct net_pkt *pkt)
{
	return &pkt->timestamp;
}

static inline void net_pkt_set_timestamp(struct net_pkt *pkt,
					 struct net_ptp_time *timestamp)
{
	pkt->timestamp.second = timestamp->second;
	pkt->timestamp.nanosecond = timestamp->nanosecond;
}
#else
static inline struct net_ptp_time *net_pkt_timestamp(struct net_pkt *pkt)
{
	ARG_UNUSED(pkt);

	return NULL;
}

static inline void net_pkt_set_timestamp(struct net_pkt *pkt,
					 struct net_ptp_time *timestamp)
{
	ARG_UNUSED(pkt);
	ARG_UNUSED(timestamp);
}
#endif /* CONFIG_NET_PKT_TIMESTAMP */

static inline size_t net_pkt_get_len(struct net_pkt *pkt)
{
	return (size_t)pkt->total_pkt_len;
}

static inline u8_t *net_pkt_ip_data(struct net_pkt *pkt)
{
	return pkt->buffer->data;
}

static inline struct net_buf *net_pkt_appdata(struct net_pkt *pkt)
{
	return pkt->appdata;
}

static inline void net_pkt_set_appdata(struct net_pkt *pkt,
				       struct net_buf *data)
{
	pkt->appdata = data;
}

void net_pkt_set_ll(struct net_pkt *pkt, u16_t hdr_len);

static inline u8_t *net_pkt_ll(struct net_pkt *pkt)
{
	if (!pkt->ll) {
		return pkt->buffer->data;
	}

	return pkt->ll;
}

static inline struct net_linkaddr *net_pkt_lladdr_src(struct net_pkt *pkt)
{
	return &pkt->lladdr_src;
}

static inline struct net_linkaddr *net_pkt_lladdr_dst(struct net_pkt *pkt)
{
	return &pkt->lladdr_dst;
}

static inline void net_pkt_lladdr_swap(struct net_pkt *pkt)
{
	u8_t *addr = net_pkt_lladdr_src(pkt)->addr;

	net_pkt_lladdr_src(pkt)->addr = net_pkt_lladdr_dst(pkt)->addr;
	net_pkt_lladdr_dst(pkt)->addr = addr;
}

static inline void net_pkt_lladdr_clear(struct net_pkt *pkt)
{
	net_pkt_lladdr_src(pkt)->addr = NULL;
	net_pkt_lladdr_src(pkt)->len = 0;
}

#if defined(CONFIG_IEEE802154) || defined(CONFIG_IEEE802154_RAW_MODE)
static inline u8_t net_pkt_ieee802154_rssi(struct net_pkt *pkt)
{
	return pkt->ieee802154_rssi;
}

static inline void net_pkt_set_ieee802154_rssi(struct net_pkt *pkt,
					       u8_t rssi)
{
	pkt->ieee802154_rssi = rssi;
}

static inline u8_t net_pkt_ieee802154_lqi(struct net_pkt *pkt)
{
	return pkt->ieee802154_lqi;
}

static inline void net_pkt_set_ieee802154_lqi(struct net_pkt *pkt,
					      u8_t lqi)
{
	pkt->ieee802154_lqi = lqi;
}
#endif

#if defined(CONFIG_NET_IPV4_AUTO)
static inline bool net_pkt_ipv4_auto(struct net_pkt *pkt)
{
	return pkt->ipv4_auto_arp_msg;
}

static inline void net_pkt_set_ipv4_auto(struct net_pkt *pkt,
					 bool is_auto_arp_msg)
{
	pkt->ipv4_auto_arp_msg = is_auto_arp_msg;
}
#else
static inline bool net_pkt_ipv4_auto(struct net_pkt *pkt)
{
	return false;
}

#define net_pkt_set_ipv4_auto(...)
#endif

#define NET_IPV6_HDR(pkt) ((struct net_ipv6_hdr *)net_pkt_ip_data(pkt))
#define NET_IPV4_HDR(pkt) ((struct net_ipv4_hdr *)net_pkt_ip_data(pkt))

static inline void net_pkt_set_src_ipv6_addr(struct net_pkt *pkt)
{
	net_if_ipv6_select_src_addr(net_context_get_iface(
					    net_pkt_context(pkt)),
				    &NET_IPV6_HDR(pkt)->src);
}

static inline void net_pkt_set_overwrite(struct net_pkt *pkt, bool overwrite)
{
	pkt->overwrite = overwrite;
}

static inline bool net_pkt_is_being_overwritten(struct net_pkt *pkt)
{
	return pkt->overwrite;
}


/* @endcond */

#if defined(CONFIG_NET_DEBUG_NET_PKT)

/**
 * @brief Debug helper to print out the buffer allocations
 */
void net_pkt_print(void);

typedef void (*net_pkt_allocs_cb_t)(struct net_pkt *pkt,
				    const char *func_alloc,
				    int line_alloc,
				    const char *func_free,
				    int line_free,
				    bool in_use,
				    void *user_data);

void net_pkt_allocs_foreach(net_pkt_allocs_cb_t cb, void *user_data);

/* Debug versions of the net_pkt functions that are used when tracking
 * buffer usage.
 */
struct net_pkt *net_pkt_alloc_debug(s32_t timeout,
				    const char *caller, int line);
#define net_pkt_alloc(_timeout)					\
	net_pkt_alloc_debug(_timeout, __func__, __LINE__)

int net_pkt_allocate_buffer_debug(struct net_pkt *pkt,
				  void *data,
				  u16_t size,
				  enum net_ip_protocol proto,
				  s32_t timeout,
				  const char *caller, int line);
#define net_pkt_allocate_buffer(_pkt, _data, _size,		\
				_proto, _timeout)		\
	net_pkt_allocate_buffer_debug(_pkt, _data, _size,	\
				      _proto, _timeout,		\
				      __func__, __LINE__)

struct net_pkt *net_pkt_allocate_with_data_debug(struct net_if *iface,
						 void *data,
						 u16_t size,
						 sa_family_t family,
						 enum net_ip_protocol proto,
						 s32_t timeout,
						 const char *caller, int line);
#define net_pkt_allocate_with_data(_iface, _data, _size,		\
				   _family, _proto, _timeout)		\
	net_pkt_allocate_with_data_debug(_iface, _data, _size,		\
					 _family, _proto, _timeout,	\
					 __func__, __LINE__)

struct net_pkt *net_pkt_allocate_with_buffer_debug(struct net_if *iface,
						   u16_t size,
						   sa_family_t family,
						   enum net_ip_protocol proto,
						   s32_t timeout,
						   const char *caller,
						   int line);
#define net_pkt_allocate_with_buffer(_iface, _size, _family,		\
				     _proto, _timeout)			\
	net_pkt_allocate_with_buffer_debug(_iface, _size, _family,	\
					   _proto, _timeout,		\
					   __func__, __LINE__)

void net_pkt_unref_debug(struct net_pkt *pkt, const char *caller, int line);
#define net_pkt_unref(pkt) net_pkt_unref_debug(pkt, __func__, __LINE__)

struct net_pkt *net_pkt_ref_debug(struct net_pkt *pkt, const char *caller,
				  int line);
#define net_pkt_ref(pkt) net_pkt_ref_debug(pkt, __func__, __LINE__)

#else /* CONFIG_NET_DEBUG_NET_PKT */

#define net_pkt_print(...)

struct net_pkt *net_pkt_alloc(s32_t timeout);

int net_pkt_allocate_buffer(struct net_pkt *pkt,
			    void *data,
			    u16_t size,
			    enum net_ip_protocol proto,
			    s32_t timeout);

struct net_pkt *net_pkt_allocate_with_data(struct net_if *iface,
					   void *data,
					   u16_t size,
					   sa_family_t family,
					   enum net_ip_protocol proto,
					   s32_t timeout);

struct net_pkt *net_pkt_allocate_with_buffer(struct net_if *iface,
					     u16_t size,
					     sa_family_t family,
					     enum net_ip_protocol proto,
					     s32_t timeout);

/**
 * @brief Place packet back into the available packets slab
 *
 * @details Releases the packet to other use. This needs to be
 * called by application after it has finished with the packet.
 *
 * @param pkt Network packet to release.
 *
 */
void net_pkt_unref(struct net_pkt *pkt);

/**
 * @brief Increase the packet ref count
 *
 * @details Mark the packet to be used still.
 *
 * @param pkt Network packet to ref.
 *
 * @return Network packet if successful, NULL otherwise.
 */
struct net_pkt *net_pkt_ref(struct net_pkt *pkt);

#endif /* CONFIG_NET_DEBUG_NET_PKT */

/**
 * @brief Initialize net_pkt iterator
 *
 * Note: This will inializet the net_pkt iterator from it's buffer.
 *
 * @param pkt The net_pkt which iterator is going to be initialized
 */
void net_pkt_iter_init(struct net_pkt *pkt);

/**
 * @brief Update a net_pkt iterator
 *
 * @param pkt    The net_pkt which iterator needs to be updated
 * @param length The length update to apply
 * @param write  Says if the length update on the iterator was writing
 */
void net_pkt_iter_update(struct net_pkt *pkt,
			 size_t length, bool write);

/**
 * @brief Backup net_pkt iterator
 *
 * @param pkt    The net_pkt which iterator is going to be backuped
 * @param backup The iterator where to backup net_pkt iterator
 */
static inline void net_pkt_iter_backup(struct net_pkt *pkt,
				       struct net_pkt_iter *backup)
{
	backup->buf = pkt->iter.buf;
	backup->pos = pkt->iter.pos;
}

/**
 * @brief Restore net_pkt iterator from a backup
 *
 * @param pkt    The net_pkt which iterator is going to be restored
 * @param backup The iterator from where to restore net_pkt iterator
 */
static inline void net_pkt_iter_restore(struct net_pkt *pkt,
					struct net_pkt_iter *backup)
{
	pkt->iter.buf = backup->buf;
	pkt->iter.pos = backup->pos;
}

/**
 * @brief Returns current position of the iterator
 *
 * @param pkt The net_pkt which iterator's position is going to be returned
 *
 * @return iterator's position
 */
static inline void *net_pkt_iter_get_pos(struct net_pkt *pkt)
{
	return pkt->iter.pos;
}

/**
 * @brief Initialize net_pkt iterator to headers location
 *
 * @param pkt The net_pkt which iterator is going to be initialized
 */
static inline void net_pkt_iter_init_to_headers(struct net_pkt *pkt)
{
	net_pkt_iter_init(pkt);
}

/**
 * @brief Initialize net_pkt iterator to application data location
 *
 * @param pkt The net_pkt which iterator is going to be initialized
 */
void net_pkt_iter_init_to_data(struct net_pkt *pkt);

/**
 * @brief Skip some data from a net_pkt
 *
 * Note: net_pkt's iterator should be properly initialized
 *       Iterator will be updated according to parameter.
 *       Depending on the value of pkt->overwrite bit, this function
 *       will affect the buffer length or not: if it's 0, skip will
 *       acually apply the move in the buffer as it had written in it.
 *
 * @param pkt    The net_pkt which iterator will be updated to skip given
 *               amount of data from the buffer.
 * @param amount Amount of data to skip in the buffer
 *
 * @return 0 in success, negative errno code otherwise.
 */
int net_pkt_skip(struct net_pkt *pkt, size_t skip);

/**
 * @brief Memset some data in a net_pkt
 *
 * Note: net_pkt's iterator should be properly initialized and,
 *       eventally, properly positioned using net_pkt_skip.
 *       Iterator will be updated according to parameter.
 *
 *
 * @param pkt    The net_pkt which iterator will be updated to skip given
 *               amount of data from the buffer.
 * @param byte   The byte to write in memory
 * @param amount Amount of data to memset with given byte
 *
 * @return 0 in success, negative errno code otherwise.
 */
int net_pkt_memset(struct net_pkt *pkt, int byte, size_t amount);

/**
 * @brief Copy data from a packet into another one.
 *
 * Note: Both net_pkt iterators should be properly initialized and,
 *       eventally, properly positioned using net_pkt_skip.
 *       Iterators will be updated according to parameters.
 *
 * @param pkt_dst Destination network packet.
 * @param pkt_src Source network packet.
 * @param length  Length of data to be copied.
 *
 * @return 0 on success, negative errno code otherwise.
 */
int net_pkt_copy(struct net_pkt *pkt_dst,
		 struct net_pkt *pkt_src,
		 size_t length);

/**
 * @brief Copy the full buffer of a net_pkt into another one.
 *
 * Note: Beware both net_pkt iterators will be initialized and modified by
 *       this function. Use net_pkt_buf_iter_backup/restore relevantly.
 *       Destination buffer needs to pre-allocated relevantly.
 *
 * @param pkt_dst Destination network packet.
 * @param pkt_src Source network packet.
 *
 * @return 0 on success, negative errno code otherwise.
 */
static inline int net_pkt_copy_all(struct net_pkt *pkt_dst,
				   struct net_pkt *pkt_src)
{
	net_pkt_iter_init(pkt_dst);
	net_pkt_iter_init(pkt_src);

	return net_pkt_copy(pkt_dst, pkt_src, net_pkt_get_len(pkt_src));
}

/**
 * @brief Clone pkt and its fragment chain.
 *
 * @param pkt Original pkt to be cloned
 * @param timeout Timeout to wait for free buffer
 *
 * @return NULL if error, cloned packet otherwise.
 */
struct net_pkt *net_pkt_clone(struct net_pkt *pkt, s32_t timeout);

/**
 * @brief Read some data from a net_pkt
 *
 * Note: net_pkt's iterator should be properly initialized and,
 *       eventally, properly positioned using net_pkt_skip.
 *       Iterator will be updated according to parameters.
 *
 * @param pkt    The network packet from where to read some data
 * @param data   The destination buffer where to copy the data
 * @param length The amount of data to copy
 *
 * @return 0 on success, negative errno code otherwise.
 */
int net_pkt_read(struct net_pkt *pkt, void *data, size_t length);

/* Read u8_t data data a net_pkt */
static inline int net_pkt_read_u8(struct net_pkt *pkt, u8_t *data)
{
	return net_pkt_read(pkt, data, 1);
}

/**
 * @brief Read u16_t big endian data from a net_pkt
 *
 * Note: net_pkt's iterator should be properly initialized and,
 *       eventally, properly positioned using net_pkt_skip.
 *       Iterator will be updated according to parameters.
 *
 * @param pkt  The network packet from where to read
 * @param data The destination u16_t where to copy the data
 *
 * @return 0 on success, negative errno code otherwise.
 */
int net_pkt_read_be16(struct net_pkt *pkt, u16_t *data);

/**
 * @brief Read u32_t big endian data from a net_pkt
 *
 * Note: net_pkt's iterator should be properly initialized and,
 *       eventally, properly positioned using net_pkt_skip.
 *       Iterator will be updated according to parameters.
 *
 * @param pkt  The network packet from where to read
 * @param data The destination u32_t where to copy the data
 *
 * @return 0 on success, negative errno code otherwise.
 */
int net_pkt_read_be32(struct net_pkt *pkt, u32_t *data);

/**
 * @brief Write data into a net_pkt
 *
 * Note: net_pkt's iterator should be properly initialized and,
 *       eventally, properly positioned using net_pkt_skip_read/write.
 *       Iterator will be updated according to parameters.
 *
 * @param pkt    Network packet.
 * @param data   Data to be written
 * @param length Length of the data to be written.
 *
 * @return 0 on success, negative errno code otherwise.
 */
int net_pkt_write(struct net_pkt *pkt, void *data, size_t length);

/* Write u8_t data into a net_pkt. */
static inline int net_pkt_write_u8(struct net_pkt *pkt, u8_t data)
{
	return net_pkt_write(pkt, &data, sizeof(u8_t));
}

/* Write u16_t big endian data into a net_pkt. */
static inline int net_pkt_write_be16(struct net_pkt *pkt, u16_t data)
{
	u16_t data_be16 = htons(data);

	return net_pkt_write(pkt, &data_be16, sizeof(u16_t));
}

/* Write u32_t big endian data into a net_pkt. */
static inline int net_pkt_write_be32(struct net_pkt *pkt, u32_t data)
{
	u32_t data_be32 = htonl(data);

	return net_pkt_write(pkt, &data_be32, sizeof(u32_t));
}

/* Write u32_t little endian data into a net_pkt. */
static inline int net_pkt_write_le32(struct net_pkt *pkt, u32_t data)
{
	u32_t data_le32 = sys_cpu_to_le32(data);

	return net_pkt_write(pkt, &data_le32, sizeof(u32_t));
}

/**
 * @brief Check if a data size could fit contiguously
 *
 * Note: net_pkt's iterator should be properly initialized and,
 *       eventally, properly positioned using net_pkt_skip_read/write.
 *
 * @param pkt  Network packet.
 * @param size The size to check contiguity
 *
 * @return true if that is the case, false otherwise.
 */
bool net_pkt_is_contiguous(struct net_pkt *pkt, size_t size);

/**
 * @brief Reduce the total length of a packet
 *
 * Note: This is meant to be used in very particular context such as
 *       removing padding at the end of a received packet or updating
 *       the overall length of a received packet which would be reused
 *       for sending a reply that would fit in less space than originally
 *       set.
 *
 * @param pkt    Network packet.
 * @param length New length of the packet
 *
 * @return 0 on sucess, negative errno code otherwise
 */
int net_pkt_reduce_length(struct net_pkt *pkt, size_t length);

/**
 * @brief Insert a buffer to a packet at the beginning of its buffer list
 *
 * @param pkt    pkt Network packet where to insert the buffer
 * @param buffer Buffer to insert
 */
void net_pkt_buf_insert(struct net_pkt *pkt, struct net_buf *buf);

/**
 * @brief Finalize the packet - only for transmission
 *
 * Note: You should not be using it, only net_send_data will.
 *
 * @param pkt pkt Network packet to finalize
 */
static inline void net_pkt_finalize(struct net_pkt *pkt)
{
	net_buf_frag_add(pkt->buffer, pkt->appdata);
}

/**
 * @brief Get source socket address.
 *
 * @param pkt Network packet
 * @param addr Source socket address
 * @param addrlen The length of source socket address
 * @return 0 on success, <0 otherwise.
 */
int net_pkt_get_src_addr(struct net_pkt *pkt,
			 struct sockaddr *addr,
			 socklen_t addrlen);

/**
 * @brief Get destination socket address.
 *
 * @param pkt Network packet
 * @param addr Destination socket address
 * @param addrlen The length of destination socket address
 * @return 0 on success, <0 otherwise.
 */
int net_pkt_get_dst_addr(struct net_pkt *pkt,
			 struct sockaddr *addr,
			 socklen_t addrlen);

/**
 * @brief Get information about predefined packet slab and data pool.
 *
 * @param pkts Pointer to RX pool is returned.
 * @param data Pointer to RX DATA pool is returned.
 */
void net_pkt_get_info(struct k_mem_slab **pkts,
		      struct net_buf_pool **data);

/**
 * @brief Convert net_pkt pointer to data pointer, cast to the specified type.
 *
 * @param _pkt  Network packet.
 * @param _type Data type to cast to on return.
 * @return Pointer of the specified type.
 *
 * @note Ensure first, that there is enough contiguous data in net_pkt
 *       with net_pkt_pullup().
 */
#define net_pkt_tod(_pkt, _type) ((_type)((_pkt)->iter.pos))

/**
 * @brief Make first len bytes contiguous.
 *
 * @param pkt Network packet.
 * @param len Length to make contiguous.
 * @return On error returns NULL and net_pkt is unrefenced,
 *         net_pkt pointer otherwise.
 */
struct net_pkt *net_pkt_pullup(struct net_pkt *pkt, int len);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_NET_NET_PKT_H_ */
