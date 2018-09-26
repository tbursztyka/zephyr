/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_NET_DEBUG_NET_PKT)
#define SYS_LOG_DOMAIN "net/pkt"
#define NET_LOG_ENABLED 1

/* This enables allocation debugging but does not print so much output
 * as that can slow things down a lot.
 */
#if !defined(CONFIG_NET_DEBUG_NET_PKT_ALL)
#define NET_SYS_LOG_LEVEL 5
#endif
#endif

#include <kernel.h>
#include <toolchain.h>
#include <string.h>
#include <zephyr/types.h>
#include <sys/types.h>

#include <misc/util.h>

#include <net/net_core.h>
#include <net/net_ip.h>
#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/udp.h>
#include <net/tcp.h>

#include "tcp_internal.h"
#include "rpl.h"

K_MEM_SLAB_DEFINE(pkts_slab, sizeof(struct net_pkt), CONFIG_NET_PKT_COUNT, 4);

#if defined(CONFIG_NET_BUF_FIXED_DATA_SIZE)

NET_BUF_POOL_FIXED_DEFINE(bufs_pool, CONFIG_NET_BUF_COUNT,	\
			  CONFIG_NET_BUF_DATA_SIZE, NULL);

static struct net_buf *pkt_allocat_buffer(size_t size,
					  bool with_loss,
					  s32_t timeout)
{
	u32_t alloc_start = k_uptime_get_32();
	struct net_buf *first = NULL;
	struct net_buf *current = NULL;

	while (size) {
		struct net_buf *new;

		new = net_buf_alloc_fixed(&bufs_pool, timeout);
		if (!new) {
			goto error;
		}

		if (!first && !current) {
			first = new;
		} else {
			current->frags = new;
		}

		current = new;
		if (current->size > size) {
			if (with_loss) {
				current->size = size;
			}

			size = 0;
		} else {
			size -= current->size;
		}

		if (timeout != K_NO_WAIT && timeout != K_FOREVER) {
			u32_t diff = k_uptime_get_32() - alloc_start;

			timeout -= min(timeout, diff);
		}
	}

	return first;
error:
	if (first) {
		net_buf_unref(first);
	}

	return NULL;
}

#else /* !CONFIG_NET_BUF_FIXED_DATA_SIZE */

NET_BUF_POOL_VAR_DEFINE(bufs_pool, CONFIG_NET_BUF_COUNT,	\
			CONFIG_NET_BUF_DATA_POOL_SIZE, NULL);

static inline struct net_buf *pkt_allocat_buffer(size_t size,
						 bool with_loss,
						 s32_t timeout)
{
	ARG_UNUSED(with_loss);

	return net_buf_alloc_len(&bufs_pool, size, timeout);
}

#endif /* CONFIG_NET_BUF_FIXED_DATA_SIZE */


#if defined(CONFIG_NET_DEBUG_NET_PKT)

#define MAX_NET_PKT_ALLOCS (CONFIG_NET_PKT_COUNT)

struct net_pkt_alloc {
	struct net_pkt *pkt;
	const char *func_alloc;
	const char *func_free;
	u16_t line_alloc;
	u16_t line_free;
	u8_t in_use;
};

static struct net_pkt_alloc net_pkt_allocs[MAX_NET_PKT_ALLOCS];

static bool net_pkt_alloc_add(struct net_pkt *pkt,
			      const char *func, int line)
{
	int i;

	for (i = 0; i < MAX_NET_PKT_ALLOCS; i++) {
		if (net_pkt_allocs[i].in_use) {
			continue;
		}

		net_pkt_allocs[i].pkt = pkt;
		net_pkt_allocs[i].in_use = true;
		net_pkt_allocs[i].func_alloc = func;
		net_pkt_allocs[i].line_alloc = line;

		return true;
	}

	return false;
}

static bool net_pkt_alloc_del(struct net_pkt *pkt, const char *func, int line)
{
	int i;

	for (i = 0; i < MAX_NET_PKT_ALLOCS; i++) {
		if (net_pkt_allocs[i].in_use &&
		    net_pkt_allocs[i].pkt == pkt) {
			net_pkt_allocs[i].func_free = func;
			net_pkt_allocs[i].line_free = line;
			net_pkt_allocs[i].in_use = false;

			return true;
		}
	}

	return false;
}

static bool net_pkt_alloc_find(struct net_pkt *pkt,
			       const char **func_free,
			       int *line_free)
{
	int i;

	for (i = 0; i < MAX_NET_PKT_ALLOCS; i++) {
		if (!net_pkt_allocs[i].in_use &&
		    net_pkt_allocs[i].pkt == pkt) {
			*func_free = net_pkt_allocs[i].func_free;
			*line_free = net_pkt_allocs[i].line_free;

			return true;
		}
	}

	return false;
}

void net_pkt_allocs_foreach(net_pkt_allocs_cb_t cb, void *user_data)
{
	int i;

	for (i = 0; i < MAX_NET_PKT_ALLOCS; i++) {
		if (net_pkt_allocs[i].in_use) {
			cb(net_pkt_allocs[i].pkt,
			   net_pkt_allocs[i].func_alloc,
			   net_pkt_allocs[i].line_alloc,
			   net_pkt_allocs[i].func_free,
			   net_pkt_allocs[i].line_free,
			   net_pkt_allocs[i].in_use,
			   user_data);
		}
	}

	for (i = 0; i < MAX_NET_PKT_ALLOCS; i++) {
		if (!net_pkt_allocs[i].in_use) {
			cb(net_pkt_allocs[i].pkt,
			   net_pkt_allocs[i].func_alloc,
			   net_pkt_allocs[i].line_alloc,
			   net_pkt_allocs[i].func_free,
			   net_pkt_allocs[i].line_free,
			   net_pkt_allocs[i].in_use,
			   user_data);
		}
	}
}

void net_pkt_print(void)
{
	NET_DBG("PKTs %u DATA %d",
		k_mem_slab_num_free_get(&pkts_slab),
		bufs_pool.avail_count);
}

#endif /* CONFIG_NET_DEBUG_NET_PKT */

static size_t pkt_buffer_length(struct net_pkt *pkt,
				size_t size,
				enum net_ip_protocol proto,
				size_t hdr_len)
{
	sa_family_t family = net_pkt_family(pkt);
	size_t max_len;

	/* Family vs iface MTU */
	if (IS_ENABLED(CONFIG_NET_IPV6) && family == AF_INET6) {
		max_len = max(net_if_get_mtu(net_pkt_iface(pkt)), NET_IPV6_MTU);
	} else if (IS_ENABLED(CONFIG_NET_IPV4) && family == AF_INET) {
		max_len = max(net_if_get_mtu(net_pkt_iface(pkt)), NET_IPV4_MTU);
	} else {
		/* AF_UNSPEC */
		max_len = net_if_get_mtu(net_pkt_iface(pkt));
	}

	max_len -= hdr_len;

	return min(size + hdr_len, max_len);
}

static size_t pkt_headers_buffer_length(struct net_pkt *pkt,
					sa_family_t family,
					enum net_ip_protocol proto)
{
	size_t hdr_len = 0;

	if (family == AF_UNSPEC) {
		return  0;
	}

	/* Family header */
	if (IS_ENABLED(CONFIG_NET_IPV6) && family == AF_INET6) {
		hdr_len += NET_IPV6H_LEN;
	} else if (IS_ENABLED(CONFIG_NET_IPV4) && family == AF_INET) {
		hdr_len += NET_IPV4H_LEN;
	}

	/* + protocol header */
	if (IS_ENABLED(CONFIG_NET_TCP) && proto == IPPROTO_TCP) {
		hdr_len += NET_TCPH_LEN + NET_TCP_MAX_OPT_SIZE;
	} else if (IS_ENABLED(CONFIG_NET_UDP) && proto == IPPROTO_UDP) {
		hdr_len += NET_UDPH_LEN;

		if (IS_ENABLED(CONFIG_NET_RPL_INSERT_HBH_OPTION)) {
			hdr_len += NET_RPL_HOP_BY_HOP_LEN;
		}
	} else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
		hdr_len += NET_ICMPH_LEN;
	}

	NET_DBG("HDRs length estimation %zu", hdr_len);

	return hdr_len;
}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
int net_pkt_allocate_buffer_debug(struct net_pkt *pkt,
				  void *data,
				  u16_t size,
				  enum net_ip_protocol proto,
				  s32_t timeout,
				  const char *caller,
				  int line)
#else
int net_pkt_allocate_buffer(struct net_pkt *pkt,
			    void *data,
			    u16_t size,
			    enum net_ip_protocol proto,
			    s32_t timeout)
#endif
{
	u32_t alloc_start = k_uptime_get_32();
	struct net_buf *app_data;
	size_t alloc_len;

	if (!size) {
		pkt->buffer = NULL;
		return 0;
	}

	if (k_is_in_isr()) {
		timeout = K_NO_WAIT;
	}

	alloc_len = pkt_headers_buffer_length(pkt,
					      net_pkt_family(pkt),
					      proto);
	if (alloc_len) {
		pkt->buffer = pkt_allocat_buffer(alloc_len, false, timeout);
		if (!pkt->buffer) {
			NET_ERR("HDRs buffer allocation failed.");
			return -ENOMEM;
		}
	}

	alloc_len = pkt_buffer_length(pkt, size, proto, alloc_len);

	NET_DBG("Data allocation maximum size %zu", alloc_len);

	if (timeout != K_NO_WAIT && timeout != K_FOREVER) {
		u32_t diff = k_uptime_get_32() - alloc_start;

		timeout -= min(timeout, diff);
	}

	if (data) {
		app_data = net_buf_alloc_with_data(&bufs_pool,
						   data, alloc_len,
						   timeout);
		net_buf_add(app_data, alloc_len);
	} else {
		app_data = pkt_allocat_buffer(alloc_len, true, timeout);
	}

	if (!app_data) {
		NET_ERR("Data buffer allocation failed.");
		net_buf_unref(pkt->buffer);
		pkt->buffer = NULL;

		return -ENOMEM;
	}

	if (!pkt->buffer) {
		pkt->buffer = app_data;
		app_data = NULL;
	}

	net_pkt_set_appdata(pkt, app_data);

#if defined(CONFIG_NET_DEBUG_NET_PKT)
	NET_DBG("%s [%d] buffer %p ref %d (%s():%d)",
		bufs_pool.name, bufs_pool.avail_count,
		pkt->buffer, pkt->buffer->ref, caller, line);
#endif

	return 0;
}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
struct net_pkt *net_pkt_alloc_debug(s32_t timeout,
				    const char *caller, int line)
#else
struct net_pkt *net_pkt_alloc(s32_t timeout)
#endif /* CONFIG_NET_DEBUG_NET_PKT */
{
	struct net_pkt *pkt;
	int ret;

	if (k_is_in_isr()) {
		timeout = K_NO_WAIT;
	}

	ret = k_mem_slab_alloc(&pkts_slab, (void **)&pkt, timeout);
	if (ret) {
		return NULL;
	}

	memset(pkt, 0, sizeof(struct net_pkt));

	pkt->ref = 1;

	net_pkt_set_priority(pkt, CONFIG_NET_TX_DEFAULT_PRIORITY);
	net_pkt_set_vlan_tag(pkt, NET_VLAN_TAG_UNSPEC);

	net_pkt_iter_init(pkt);

#if defined(CONFIG_NET_DEBUG_NET_PKT)
	net_pkt_alloc_add(pkt, caller, line);

	NET_DBG("[%u] pkt %p ref %d (%s():%d)",
		k_mem_slab_num_free_get(&pkts_slab),
		pkt, pkt->ref, caller, line);
#endif

	return pkt;
}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
struct net_pkt *net_pkt_ref_debug(struct net_pkt *pkt,
				  const char *caller, int line)
#else
struct net_pkt *net_pkt_ref(struct net_pkt *pkt)
#endif /* CONFIG_NET_DEBUG_NET_PKT */
{
	if (!pkt) {
		NET_ERR("*** ERROR *** pkt %p (%s():%d)", pkt, caller, line);
		return NULL;
	}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
	NET_DBG("[%d] pkt %p ref %d (%s():%d)",
		k_mem_slab_num_free_get(&pkts_slab),
		pkt, pkt->ref + 1, caller, line);
#endif

	pkt->ref++;

	return pkt;
}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
void net_pkt_unref_debug(struct net_pkt *pkt,
			 const char *caller, int line)
#else
void net_pkt_unref(struct net_pkt *pkt)
#endif /* CONFIG_NET_DEBUG_NET_PKT */
{
	if (!pkt) {
		NET_ERR("*** ERROR *** pkt %p (%s():%d)", pkt, caller, line);
		return;
	}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
	if (!pkt->ref) {
		const char *func_freed;
		int line_freed;

		if (net_pkt_alloc_find(pkt, &func_freed, &line_freed)) {
			NET_ERR("*** ERROR *** pkt %p is freed already by "
				"%s():%d (%s():%d)",
				pkt, func_freed, line_freed, caller, line);
		} else {
			NET_ERR("*** ERROR *** pkt %p is freed already "
				"(%s():%d)", pkt, caller, line);
		}

		return;
	} else if (pkt->ref == 1) {
		net_pkt_alloc_del(pkt, caller, line);
	}
#else
	if (!pkt->ref) {
		return;
	}
#endif

	if (--pkt->ref > 0) {
		return;
	}

	if (pkt->buffer) {
		net_buf_unref(pkt->buffer);
	}

	k_mem_slab_free(&pkts_slab, (void **)&pkt);
}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
struct net_pkt *net_pkt_alloc_on_iface_debug(struct net_if *iface,
					     s32_t timeout,
					     const char *caller,
					     int line)
#else
struct net_pkt *net_pkt_alloc_on_iface(struct net_if *iface, s32_t timeout)
#endif
{
	struct net_pkt *pkt;

#if defined(CONFIG_NET_DEBUG_NET_PKT)
	pkt = net_pkt_alloc_debug(timeout, caller, line);
#else
	pkt = net_pkt_alloc(timeout);
#endif
	if (pkt) {
		net_pkt_set_iface(pkt, iface);
	}

	return pkt;
}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
struct net_pkt *net_pkt_allocate_with_data_debug(struct net_if *iface,
						 void *data,
						 u16_t size,
						 sa_family_t family,
						 enum net_ip_protocol proto,
						 s32_t timeout,
						 const char *caller,
						 int line)
#else
struct net_pkt *net_pkt_allocate_with_data(struct net_if *iface,
					   void *data,
					   u16_t size,
					   sa_family_t family,
					   enum net_ip_protocol proto,
					   s32_t timeout)
#endif
{
	u32_t alloc_start = k_uptime_get_32();
	struct net_pkt *pkt;
	int ret;

	NET_DBG("On iface %p data %p size %zu", iface, data, size);

#if defined(CONFIG_NET_DEBUG_NET_PKT)
	pkt = net_pkt_alloc_on_iface_debug(iface, timeout, caller, line);
#else
	pkt = net_pkt_alloc_on_iface(iface, timeout);
#endif
	if (!pkt) {
		return NULL;
	}

	net_pkt_set_family(pkt, family);

	if (timeout != K_NO_WAIT && timeout != K_FOREVER) {
		u32_t diff = k_uptime_get_32() - alloc_start;

		timeout -= min(timeout, diff);
	}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
	ret = net_pkt_allocate_buffer_debug(pkt, data, size, proto, timeout,
					    caller, line);
#else
	ret = net_pkt_allocate_buffer(pkt, data, size, proto, timeout);
#endif
	if (ret) {
		net_pkt_unref(pkt);
		return NULL;
	}

	net_pkt_iter_init(pkt);

	return pkt;
}

#if defined(CONFIG_NET_DEBUG_NET_PKT)
struct net_pkt *net_pkt_allocate_with_buffer_debug(struct net_if *iface,
						   u16_t size,
						   sa_family_t family,
						   enum net_ip_protocol proto,
						   s32_t timeout,
						   const char *caller,
						   int line)
{
	return net_pkt_allocate_with_data_debug(iface, NULL, size,
						family, proto, timeout,
						caller, line);
}
#else
struct net_pkt *net_pkt_allocate_with_buffer(struct net_if *iface,
					     u16_t size,
					     sa_family_t family,
					     enum net_ip_protocol proto,
					     s32_t timeout)
{
	return net_pkt_allocate_with_data(iface, NULL, size,
					  family, proto, timeout);
}
#endif

int net_pkt_reduce_length(struct net_pkt *pkt, size_t length)
{
	struct net_buf *buf = pkt->buffer;

	pkt->total_pkt_len = 0;

	while (buf && length) {
		if (buf->len < length) {
			length -= buf->len;
		} else {
			buf->len = length;
			length = 0;
		}

		pkt->total_pkt_len += buf->len;
		buf = buf->frags;
	}

	if (!buf || length) {
		return -EINVAL;
	}

	return 0;
}

static void pkt_iter_init(struct net_pkt *pkt, struct net_buf *buffer)
{
	pkt->iter.buf = buffer;
	if (pkt->iter.buf) {
		pkt->iter.pos = pkt->iter.buf->data;
	} else {
		pkt->iter.pos = NULL;
	}
}

void net_pkt_iter_init(struct net_pkt *pkt)
{
	pkt_iter_init(pkt, pkt->buffer);
}

void net_pkt_iter_init_to_data(struct net_pkt *pkt)
{
	pkt_iter_init(pkt, pkt->appdata);
}

void net_pkt_iter_update(struct net_pkt *pkt,
			 size_t length, bool write)
{
	struct net_pkt_iter *iter = &pkt->iter;
	size_t len;

	if (net_pkt_is_being_overwritten(pkt)) {
		write = false;
	}

	len = write ? iter->buf->size : iter->buf->len;
	if ((length + (iter->pos - (void *)iter->buf->data)) == len) {
		iter->buf = iter->buf->frags;
		if (iter->buf) {
			iter->pos = iter->buf->data;
		} else {
			iter->pos = NULL;
		}
	} else {
		iter->pos += length;
	}

	if (write) {
		pkt->total_pkt_len += length;
	}
}

/* Internal function that does all operation (skip/read/write/memset)
 * memset is obtain by setting operator to NULL and write to true.
 */
static int net_pkt_iter_operate(struct net_pkt *pkt,
				void *data, size_t length,
				bool copy, bool write)
{
	/* We use such variable to avoid lengthy lines */
	struct net_pkt_iter *iter = &pkt->iter;

	while (iter->buf && length) {
		size_t d_len, len;

		if (write && !net_pkt_is_being_overwritten(pkt)) {
			d_len = iter->buf->size -
				(iter->pos - (void *)iter->buf->data);
		} else {
			d_len = iter->buf->len -
				(iter->pos - (void *)iter->buf->data);
		}

		if (length < d_len) {
			len = length;
		} else {
			len = d_len;
		}

		if (copy) {
			memcpy(write ? iter->pos : data,
			       write ? data : iter->pos,
			       len);
		} else if (data) {
			memset(iter->pos, *(int*)data, len);
		}

		if (write && !net_pkt_is_being_overwritten(pkt)) {
			net_buf_add(iter->buf, len);
		}

		net_pkt_iter_update(pkt, len, write);

		if (copy && data) {
			data += len;
		}

		length -= len;
	}

	/* Iterator having NULL as buf would not be an error
	 * if we just read/wrote/skipped until the end of the buffer.
	 */
	if (!iter->buf && length) {
		NET_ERR("Still some length to go %zu", length);
		return -ENOBUFS;
	}

	return 0;
}

int net_pkt_skip(struct net_pkt *pkt, size_t skip)
{
	return net_pkt_iter_operate(pkt, NULL, skip, false, true);
}

int net_pkt_memset(struct net_pkt *pkt, int byte, size_t amount)
{
	return net_pkt_iter_operate(pkt, &byte, amount, false, true);
}

int net_pkt_read(struct net_pkt *pkt, void *data, size_t length)
{
	return net_pkt_iter_operate(pkt, data, length, true, false);
}

int net_pkt_read_be16(struct net_pkt *pkt, u16_t *data)
{
	u8_t d16[2];
	int ret;

	ret = net_pkt_read(pkt, d16, sizeof(u16_t));

	*data = d16[0] << 8 | d16[1];

	return ret;
}

int net_pkt_read_be32(struct net_pkt *pkt, u32_t *data)
{
	u8_t d32[4];
	int ret;

	ret = net_pkt_read(pkt, d32, sizeof(u32_t));

	*data = d32[0] << 24 | d32[1] << 16 | d32[2] << 8 | d32[3];

	return ret;
}

int net_pkt_write(struct net_pkt *pkt, void *data, size_t length)
{
	return net_pkt_iter_operate(pkt, data, length, true, true);
}

int net_pkt_copy(struct net_pkt *pkt_dst,
		 struct net_pkt *pkt_src,
		 size_t length)
{
	struct net_pkt_iter *i_dst = &pkt_dst->iter;
	struct net_pkt_iter *i_src = &pkt_src->iter;

	while (i_dst->buf && i_src->buf && length) {
		size_t s_len, d_len, len;

		s_len = i_src->buf->len -
			(i_src->pos - (void *)i_src->buf->data);
		d_len = i_dst->buf->size -
			(i_dst->pos - (void *)i_dst->buf->data);
		if (length < s_len && length < d_len) {
			len = length;
		} else {
			if (length < s_len) {
				len = d_len;
			} else {
				len = s_len;
			}
		}

		memcpy(i_dst->pos, i_src->pos, len);

		length -= len;

		if (!net_pkt_is_being_overwritten(pkt_dst)) {
			net_buf_add(i_dst->buf, len);
		}

		net_pkt_iter_update(pkt_dst, len, true);
		net_pkt_iter_update(pkt_src, len, false);
	}

	if ((!i_dst->buf || !i_src->buf) && length) {
		return -ENOBUFS;
	}

	return 0;
}

struct net_pkt *net_pkt_clone(struct net_pkt *pkt, s32_t timeout)
{
	struct net_pkt *clone_pkt;

	clone_pkt = net_pkt_allocate_with_buffer(net_pkt_iface(pkt),
						 net_pkt_get_len(pkt),
						 AF_UNSPEC, 0, timeout);
	if (!clone_pkt) {
		return NULL;
	}

	net_pkt_iter_init(pkt);

	if (net_pkt_copy_all(clone_pkt, pkt)) {
		net_pkt_unref(clone_pkt);
		return NULL;
	}

	if (clone_pkt->buffer) {
		/* The link header pointers are only usable if there is
		 * a buffer that we copied because those pointers point
		 * to start of the fragment which we do not have right now.
		 */
		memcpy(&clone_pkt->lladdr_src, &pkt->lladdr_src,
		       sizeof(clone_pkt->lladdr_src));
		memcpy(&clone_pkt->lladdr_dst, &pkt->lladdr_dst,
		       sizeof(clone_pkt->lladdr_dst));
	}

	net_pkt_set_family(clone_pkt, net_pkt_family(pkt));
	net_pkt_set_context(clone_pkt, net_pkt_context(pkt));
	net_pkt_set_token(clone_pkt, net_pkt_token(pkt));

	net_pkt_set_next_hdr(clone_pkt, NULL);
	net_pkt_set_ip_hdr_len(clone_pkt, net_pkt_ip_hdr_len(pkt));
	net_pkt_set_vlan_tag(clone_pkt, net_pkt_vlan_tag(pkt));

	if (IS_ENABLED(CONFIG_NET_IPV4) && net_pkt_family(pkt) == AF_INET) {
		net_pkt_set_ipv4_ttl(clone_pkt, net_pkt_ipv4_ttl(pkt));
	} else if (IS_ENABLED(CONFIG_NET_IPV6) &&
		   net_pkt_family(pkt) == AF_INET6) {
		net_pkt_set_ipv6_hop_limit(clone_pkt,
					   net_pkt_ipv6_hop_limit(pkt));
		net_pkt_set_ipv6_ext_len(clone_pkt, net_pkt_ipv6_ext_len(pkt));
		net_pkt_set_ipv6_ext_opt_len(clone_pkt,
					     net_pkt_ipv6_ext_opt_len(pkt));
		net_pkt_set_ipv6_hdr_prev(clone_pkt,
					  net_pkt_ipv6_hdr_prev(pkt));
	}

	NET_DBG("Cloned %p to %p", pkt, clone_pkt);

	return clone_pkt;
}

bool net_pkt_is_contiguous(struct net_pkt *pkt, size_t size)
{
	struct net_pkt_iter *iter = &pkt->iter;
	size_t len;

	NET_ASSERT(iter->buf && iter->pos);

	len = net_pkt_is_being_overwritten(pkt) ?
		iter->buf->len : iter->buf->size;
	len -= iter->pos - (void *)iter->buf->data;
	if (len >= size) {
		return true;
	}

	return false;
}

void net_pkt_buf_insert(struct net_pkt *pkt, struct net_buf *buf)
{
	net_buf_frag_last(buf)->frags = pkt->buffer;
	pkt->buffer = buf;
}

void net_pkt_set_ll(struct net_pkt *pkt, u16_t hdr_len)
{
	pkt->ll = pkt->buffer->data;
	pkt->total_pkt_len -= hdr_len;
	net_buf_pull(pkt->buffer, hdr_len);
}

void net_pkt_get_info(struct k_mem_slab **pkts,
		      struct net_buf_pool **data)
{
	if (pkts) {
		*pkts = &pkts_slab;
	}

	if (data) {
		*data = &bufs_pool;
	}
}

struct net_pkt *net_pkt_pullup(struct net_pkt *pkt, int len)
{
	bool error = false;

	net_pkt_iter_init(pkt);

	if (net_pkt_is_contiguous(pkt, len) == false) {

		if (net_pkt_skip(pkt, len) < 0) {
			net_pkt_unref(pkt);
			error = true;
		} else {
			net_pkt_iter_init(pkt);
		}
	}

	return error ? NULL : pkt;
}

void net_pkt_init(void)
{
	NET_DBG("Allocating %u packets (%zu bytes) and %d net_buf (%u bytes)",
		k_mem_slab_num_free_get(&pkts_slab),
		(size_t)(k_mem_slab_num_free_get(&pkts_slab) *
			 sizeof(struct net_pkt)),
		bufs_pool.avail_count, bufs_pool.pool_size);
}
