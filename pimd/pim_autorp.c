// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_autorp.c: PIM AutoRP handling routines
 *
 * Copyright (C) 2024 ATCorp
 * Nathan Bahr
 */

#include <zebra.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "lib/plist.h"
#include "lib/plist_int.h"
#include "lib/sockopt.h"
#include "lib/network.h"
#include "lib/termtable.h"
#include "lib/json.h"

#include "pimd.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_sock.h"
#include "pim_instance.h"
#include "pim_autorp.h"
#include "pim_util.h"

DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP, "PIM AutoRP info");
DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP_RP, "PIM AutoRP advertised RP info");
DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP_CRP, "PIM AutoRP candidate RP info");
DEFINE_MTYPE_STATIC(PIMD, PIM_AUTORP_ANNOUNCE, "PIM AutoRP announcement packet");

static const char *PIM_AUTORP_ANNOUNCEMENT_GRP = "224.0.1.39";
static const char *PIM_AUTORP_DISCOVERY_GRP = "224.0.1.40";
static const in_port_t PIM_AUTORP_PORT = 496;

static int pim_autorp_rp_cmp(const struct pim_autorp_rp *l,
			     const struct pim_autorp_rp *r)
{
	return pim_addr_cmp(l->addr, r->addr);
}

DECLARE_SORTLIST_UNIQ(pim_autorp_rp, struct pim_autorp_rp, list,
		      pim_autorp_rp_cmp);

static void pim_autorp_rp_free(struct pim_autorp_rp *rp)
{
	event_cancel(&rp->hold_timer);

	/* Clean up installed RP info */
	if (pim_rp_del(rp->autorp->pim, rp->addr, rp->grp,
		       (strlen(rp->grplist) ? rp->grplist : NULL),
		       RP_SRC_AUTORP))
		if (PIM_DEBUG_AUTORP)
			zlog_err("%s: Failed to delete RP %pI4", __func__,
				 &rp->addr);

	XFREE(MTYPE_PIM_AUTORP_RP, rp);
}

static void pim_autorp_rplist_free(struct pim_autorp_rp_head *head)
{
	struct pim_autorp_rp *rp;

	while ((rp = pim_autorp_rp_pop(head)))
		pim_autorp_rp_free(rp);
}

static void pim_autorp_free(struct pim_autorp *autorp)
{
	pim_autorp_rplist_free(&(autorp->discovery_rp_list));
	pim_autorp_rp_fini(&(autorp->discovery_rp_list));
}

static bool pim_autorp_join_groups(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct pim_autorp *autorp;
	pim_addr grp;

	pim_ifp = ifp->info;
	pim = pim_ifp->pim;
	autorp = pim->autorp;

	inet_pton(PIM_AF, PIM_AUTORP_DISCOVERY_GRP, &grp);
	if (pim_socket_join(autorp->sock, grp, pim_ifp->primary_address,
			    ifp->ifindex, pim_ifp)) {
		zlog_err("Failed to join group %pI4 on interface %s", &grp,
			 ifp->name);
		return false;
	}

	/* TODO: Future Mapping agent implementation
	 *  Join announcement group for AutoRP mapping agent
	 * inet_pton(PIM_AF, PIM_AUTORP_ANNOUNCEMENT_GRP, &grp);
	 * if (pim_socket_join(pim->autorp->sock, grp,
	 *              pim_ifp->primary_address,
	 *              ifp->ifindex, pim_ifp)) {
	 *  zlog_err("Failed to join group %pI4 on interface %s",
	 *          &grp, ifp->name);
	 *  return errno;
	 * }
	 */

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Joined AutoRP groups on interface %s", __func__,
			   ifp->name);

	return true;
}

static bool pim_autorp_leave_groups(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct pim_autorp *autorp;
	pim_addr grp;

	pim_ifp = ifp->info;
	pim = pim_ifp->pim;
	autorp = pim->autorp;

	inet_pton(PIM_AF, PIM_AUTORP_DISCOVERY_GRP, &grp);
	if (pim_socket_leave(autorp->sock, grp, pim_ifp->primary_address,
			     ifp->ifindex, pim_ifp)) {
		zlog_err("Failed to leave group %pI4 on interface %s", &grp,
			 ifp->name);
		return false;
	}

	/* TODO: Future Mapping agent implementation
	 *  Leave announcement group for AutoRP mapping agent
	 * inet_pton(PIM_AF, PIM_AUTORP_ANNOUNCEMENT_GRP, &grp);
	 * if (pim_socket_leave(pim->autorp->sock, grp,
	 *              pim_ifp->primary_address,
	 *              ifp->ifindex, pim_ifp)) {
	 *  zlog_err("Failed to leave group %pI4 on interface %s",
	 *           &grp, ifp->name);
	 *  return errno;
	 * }
	 */

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Left AutoRP groups on interface %s", __func__,
			   ifp->name);

	return true;
}

static bool pim_autorp_setup(struct pim_autorp *autorp)
{
#if defined(HAVE_IP_PKTINFO)
	int data;
	socklen_t data_len = sizeof(data);
#endif

	struct sockaddr_in autorp_addr = { .sin_family = AF_INET,
					   .sin_addr = { .s_addr = INADDR_ANY },
					   .sin_port = htons(PIM_AUTORP_PORT) };

	setsockopt_so_recvbuf(autorp->sock, 1024 * 1024 * 8);

#if defined(HAVE_IP_PKTINFO)
	/* Linux and Solaris IP_PKTINFO */
	data = 1;
	if (setsockopt(autorp->sock, PIM_IPPROTO, IP_PKTINFO, &data, data_len)) {
		zlog_err("Could not set IP_PKTINFO on socket fd=%d: errno=%d: %s",
			 autorp->sock, errno, safe_strerror(errno));
		return false;
	}
#endif

	if (set_nonblocking(autorp->sock) < 0) {
		zlog_err("Could not set non blocking on socket fd=%d: errno=%d: %s",
			 autorp->sock, errno, safe_strerror(errno));
		return false;
	}

	if (sockopt_reuseaddr(autorp->sock)) {
		zlog_err("Could not set reuse addr on socket fd=%d: errno=%d: %s",
			 autorp->sock, errno, safe_strerror(errno));
		return false;
	}

	if (bind(autorp->sock, (const struct sockaddr *)&autorp_addr,
		 sizeof(autorp_addr)) < 0) {
		zlog_err("Could not bind socket: %pSUp, fd=%d, errno=%d, %s",
			 (union sockunion *)&autorp_addr, autorp->sock, errno,
			 safe_strerror(errno));
		return false;
	}

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP finished setup", __func__);

	return true;
}

static bool pim_autorp_announcement(struct pim_autorp *autorp, uint8_t rpcnt,
				    uint16_t holdtime, char *buf,
				    size_t buf_size)
{
	/* TODO: Future Mapping agent implementation
	 *  Implement AutoRP mapping agent logic using received announcement messages
	 */
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP processed announcement message",
			   __func__);
	return true;
}

static void autorp_rp_holdtime(struct event *evt)
{
	/* RP hold time expired, remove the RP */
	struct pim_autorp_rp *rp = EVENT_ARG(evt);

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP hold time expired, RP removed: addr=%pI4, grp=%pFX, grplist=%s",
			   __func__, &rp->addr, &rp->grp,
			   (strlen(rp->grplist) ? rp->grplist : "NONE"));

	pim_autorp_rp_del(&(rp->autorp->discovery_rp_list), rp);
	pim_autorp_rp_free(rp);
}

static bool pim_autorp_add_rp(struct pim_autorp *autorp, pim_addr rpaddr,
			      struct prefix grp, char *listname,
			      uint16_t holdtime)
{
	struct pim_autorp_rp *rp;
	struct pim_autorp_rp *trp = NULL;
	int ret;

	ret = pim_rp_new(autorp->pim, rpaddr, grp, listname, RP_SRC_AUTORP);
	/* There may not be a path to the RP right now, but that doesn't mean it failed to add the RP */
	if (ret != PIM_SUCCESS && ret != PIM_RP_NO_PATH) {
		zlog_err("%s: Failed to add new RP addr=%pI4, grp=%pFX, grplist=%s",
			 __func__, &rpaddr, &grp,
			 (listname ? listname : "NONE"));
		return false;
	}

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Added new AutoRP learned RP addr=%pI4, grp=%pFX, grplist=%s",
			   __func__, &rpaddr, &grp,
			   (listname ? listname : "NONE"));

	rp = XCALLOC(MTYPE_PIM_AUTORP_RP, sizeof(*rp));
	rp->autorp = autorp;
	memcpy(&(rp->addr), &rpaddr, sizeof(pim_addr));
	prefix_copy(&(rp->grp), &grp);
	if (listname)
		snprintf(rp->grplist, sizeof(rp->grplist), "%s", listname);
	else
		rp->grplist[0] = '\0';

	rp->holdtime = holdtime;
	rp->hold_timer = NULL;
	trp = pim_autorp_rp_add(&(autorp->discovery_rp_list), rp);
	if (trp == NULL) {
		/* RP was brand new */
		trp = pim_autorp_rp_find(&(autorp->discovery_rp_list),
					 (const struct pim_autorp_rp *)rp);
	} else {
		/* RP already existed */
		XFREE(MTYPE_PIM_AUTORP_RP, rp);
		event_cancel(&trp->hold_timer);

		/* We know the address matches, but these values may have changed */
		trp->holdtime = holdtime;
		prefix_copy(&(trp->grp), &grp);
		if (listname) {
			snprintf(trp->grplist, sizeof(trp->grplist), "%s",
				 listname);
		} else {
			trp->grplist[0] = '\0';
		}
	}

	if (holdtime > 0) {
		event_add_timer(router->master, autorp_rp_holdtime, trp,
				holdtime, &(trp->hold_timer));
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: Started %u second hold timer for RP %pI4", __func__,
				   holdtime, &trp->addr);
	} else {
		/* If hold time is zero, make sure there doesn't exist a hold timer for it already */
		event_cancel(&trp->hold_timer);
	}

	return true;
}

static bool pim_autorp_discovery(struct pim_autorp *autorp, uint8_t rpcnt,
				 uint16_t holdtime, char *buf, size_t buf_size)
{
	int i, j;
	struct autorp_pkt_rp *rp;
	struct autorp_pkt_grp *grp;
	size_t offset = 0;
	pim_addr rp_addr;
	struct prefix grppfix = {};
	char plname[32];
	struct prefix_list *pl;
	struct prefix_list_entry *ple;
	int64_t seq = 1;
	bool success = true;

	for (i = 0; i < rpcnt; ++i) {
		if ((buf_size - offset) < AUTORP_RPLEN)
			return false;

		rp = (struct autorp_pkt_rp *)(buf + offset);
		offset += AUTORP_RPLEN;

		rp_addr.s_addr = rp->addr;

		/* Ignore RP's limited to PIM version 1 or with an unknown version */
		if (rp->pimver == PIM_V1 || rp->pimver == PIM_VUNKNOWN) {
			zlog_warn("%s: Ignoring unsupported PIM version in AutoRP Discovery for RP %pI4",
				  __func__, (in_addr_t *)&(rp->addr));
			/* Update the offset to skip past the groups advertised for this RP */
			offset += (AUTORP_GRPLEN * rp->grpcnt);
			continue;
		}


		if (rp->grpcnt == 0) {
			/* No groups?? */
			zlog_warn("%s: Discovery message has no groups for RP %pI4",
				  __func__, (in_addr_t *)&(rp->addr));
			continue;
		}

		if ((buf_size - offset) < AUTORP_GRPLEN) {
			zlog_warn("%s: Buffer underrun parsing groups for RP %pI4",
				  __func__, (in_addr_t *)&(rp->addr));
			return false;
		}

		grp = (struct autorp_pkt_grp *)(buf + offset);
		offset += AUTORP_GRPLEN;

		if (rp->grpcnt == 1 && grp->negprefix == 0) {
			/* Only one group with positive prefix, we can use the standard RP API */
			grppfix.family = AF_INET;
			grppfix.prefixlen = grp->masklen;
			grppfix.u.prefix4.s_addr = grp->addr;
			if (!pim_autorp_add_rp(autorp, rp_addr, grppfix, NULL,
					       holdtime))
				success = false;
		} else {
			/* More than one grp, or the only group is a negative prefix, need to make a prefix list for this RP */
			snprintfrr(plname, sizeof(plname), "__AUTORP_%pI4__",
				   &rp_addr);
			pl = prefix_list_get(AFI_IP, 0, plname);

			for (j = 0; j < rp->grpcnt; ++j) {
				/* grp is already pointing at the first group in the buffer */
				ple = prefix_list_entry_new();
				ple->pl = pl;
				ple->seq = seq;
				seq += 5;
				memset(&ple->prefix, 0, sizeof(ple->prefix));
				prefix_list_entry_update_start(ple);
				ple->type = (grp->negprefix ? PREFIX_DENY
							    : PREFIX_PERMIT);
				ple->prefix.family = AF_INET;
				ple->prefix.prefixlen = grp->masklen;
				ple->prefix.u.prefix4.s_addr = grp->addr;
				ple->any = false;
				ple->ge = 0;
				ple->le = 32;
				prefix_list_entry_update_finish(ple);

				if ((buf_size - offset) < AUTORP_GRPLEN)
					return false;

				grp = (struct autorp_pkt_grp *)(buf + offset);
				offset += AUTORP_GRPLEN;
			}

			if (!pim_autorp_add_rp(autorp, rp_addr, grppfix, plname,
					       holdtime))
				success = false;
		}
	}

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Processed AutoRP Discovery message", __func__);

	return success;
}

static bool pim_autorp_msg(struct pim_autorp *autorp, char *buf, size_t buf_size)
{
	struct autorp_pkt_hdr *h;

	if (buf_size < AUTORP_HDRLEN)
		return false;

	h = (struct autorp_pkt_hdr *)buf;

	if (h->version != AUTORP_VERSION)
		return false;

	if (h->type == AUTORP_ANNOUNCEMENT_TYPE &&
	    !pim_autorp_announcement(autorp, h->rpcnt, htons(h->holdtime),
				     buf + AUTORP_HDRLEN,
				     buf_size - AUTORP_HDRLEN))
		return false;

	if (h->type == AUTORP_DISCOVERY_TYPE &&
	    !pim_autorp_discovery(autorp, h->rpcnt, htons(h->holdtime),
				  buf + AUTORP_HDRLEN, buf_size - AUTORP_HDRLEN))
		return false;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Processed AutoRP packet", __func__);

	return true;
}

static void autorp_read(struct event *t);

static void autorp_read_on(struct pim_autorp *autorp)
{
	event_add_read(router->master, autorp_read, autorp, autorp->sock,
		       &(autorp->read_event));
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket read enabled", __func__);
}

static void autorp_read_off(struct pim_autorp *autorp)
{
	event_cancel(&(autorp->read_event));
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket read disabled", __func__);
}

static void autorp_read(struct event *evt)
{
	struct pim_autorp *autorp = evt->arg;
	int fd = evt->u.fd;
	char buf[10000];
	int rd;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: Reading from AutoRP socket", __func__);

	while (1) {
		rd = pim_socket_recvfromto(fd, (uint8_t *)buf, sizeof(buf),
					   NULL, NULL, NULL, NULL, NULL);
		if (rd <= 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			zlog_warn("%s: Failure reading rd=%d: fd=%d: errno=%d: %s",
				  __func__, rd, fd, errno, safe_strerror(errno));
			goto err;
		}

		if (!pim_autorp_msg(autorp, buf, rd))
			zlog_err("%s: Failure parsing AutoRP message", __func__);
		/* Keep reading until would block */
	}

	/* No error, enable read again */
	autorp_read_on(autorp);

err:
	return;
}

static bool pim_autorp_socket_enable(struct pim_autorp *autorp)
{
	int fd;

	frr_with_privs (&pimd_privs) {
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		if (fd < 0) {
			zlog_warn("Could not create autorp socket: errno=%d: %s",
				  errno, safe_strerror(errno));
			return false;
		}

		autorp->sock = fd;
		if (!pim_autorp_setup(autorp)) {
			zlog_warn("Could not setup autorp socket fd=%d: errno=%d: %s",
				  fd, errno, safe_strerror(errno));
			close(fd);
			autorp->sock = -1;
			return false;
		}
	}

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket enabled", __func__);

	return true;
}

static bool pim_autorp_socket_disable(struct pim_autorp *autorp)
{
	if (close(autorp->sock)) {
		zlog_warn("Failure closing autorp socket: fd=%d errno=%d: %s",
			  autorp->sock, errno, safe_strerror(errno));
		return false;
	}

	autorp_read_off(autorp);
	autorp->sock = -1;

	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP socket disabled", __func__);

	return true;
}

static void autorp_send_announcement(struct event *evt)
{
	struct pim_autorp *autorp = EVENT_ARG(evt);
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct sockaddr_in announceGrp;

	announceGrp.sin_family = AF_INET;
	announceGrp.sin_port = htons(PIM_AUTORP_PORT);
	inet_pton(PIM_AF, PIM_AUTORP_ANNOUNCEMENT_GRP, &announceGrp.sin_addr);

	if (autorp->annouce_pkt_sz >= MIN_AUTORP_PKT_SZ) {
		if (setsockopt(autorp->sock, IPPROTO_IP, IP_MULTICAST_TTL,
			       &(autorp->announce_scope),
			       sizeof(autorp->announce_scope)) < 0) {
			if (PIM_DEBUG_AUTORP)
				zlog_err("%s: Failed to set Multicast TTL for sending AutoRP announcement message, errno=%d, %s",
					 __func__, errno, safe_strerror(errno));
		}

		FOR_ALL_INTERFACES (autorp->pim->vrf, ifp) {
			pim_ifp = ifp->info;
			/* Only send on active interfaces with full pim enabled, non-passive
			 * and have a primary address set.
			 */
			if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) &&
			    pim_ifp && pim_ifp->pim_enable &&
			    !pim_ifp->pim_passive_enable &&
			    !pim_addr_is_any(pim_ifp->primary_address)) {
				if (setsockopt(autorp->sock, IPPROTO_IP,
					       IP_MULTICAST_IF,
					       &(pim_ifp->primary_address),
					       sizeof(pim_ifp->primary_address)) <
				    0) {
					if (PIM_DEBUG_AUTORP)
						zlog_err("%s: Failed to set Multicast Interface for sending AutoRP announcement message, errno=%d, %s",
							 __func__, errno,
							 safe_strerror(errno));
				}
				if (sendto(autorp->sock, autorp->annouce_pkt,
					   autorp->annouce_pkt_sz, 0,
					   (struct sockaddr *)&announceGrp,
					   sizeof(announceGrp)) <= 0) {
					if (PIM_DEBUG_AUTORP)
						zlog_err("%s: Failed to send AutoRP announcement message, errno=%d, %s",
							 __func__, errno,
							 safe_strerror(errno));
				}
			}
		}
	}

	/* Start the new timer for the entire announce interval */
	event_add_timer(router->master, autorp_send_announcement, autorp,
			autorp->announce_interval, &(autorp->announce_timer));
}

static void autorp_announcement_on(struct pim_autorp *autorp)
{
	int interval = 5;

	if (interval > autorp->announce_interval) {
		/* If the configured interval is less than 5 seconds, then just use that */
		interval = autorp->announce_interval;
	}
	event_add_timer(router->master, autorp_send_announcement, autorp,
			interval, &(autorp->announce_timer));
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP announcement sending enabled", __func__);
}

static void autorp_announcement_off(struct pim_autorp *autorp)
{
	event_cancel(&(autorp->announce_timer));
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP announcement sending disabled", __func__);
}

/* Build the new announcement packet.
 * If there is a packet to send, restart the send timer with a short wait
 */
static void pim_autorp_new_announcement(struct pim_instance *pim)
{
	struct pim_autorp *autorp = pim->autorp;
	struct autorp_pkt_hdr *hdr;
	struct autorp_pkt_rp *rp;
	struct autorp_pkt_grp *grp;
	int32_t holdtime;

	if (!autorp)
		return;

	/* First disable any existing send timer */
	autorp_announcement_off(autorp);

	/* No candidate RP source configured yet */
	if (!autorp->cand_rp_addrsel.run)
		return;

	/* No group or prefix list configured yet */
	if (is_default_prefix(&autorp->cand_rp_grplist.grp) && autorp->cand_rp_grplist.plist == NULL)
		return;

	/* If reading from a prefix list, make sure it exists */
	if (autorp->cand_rp_grplist.plist && prefix_list_lookup(AFI_IP, autorp->cand_rp_grplist.plist) == NULL)
		return;

	/* Determine the holdtime for the packet */
	holdtime = autorp->announce_holdtime;
	if (holdtime == DEFAULT_ANNOUNCE_HOLDTIME)
		holdtime = autorp->announce_interval * 3;
	if (holdtime > UINT16_MAX)
		holdtime = UINT16_MAX;

	/*
	 * First time building, allocate the space
	 * We only ever pack one RP, so allocate the max for one RP and 255 groups so we don't need to
	 * reallocate later. This should be ok since we are only allocating the memory once for a
	 * single packet (potentially per vrf)
	 */
	if (!autorp->annouce_pkt)
		autorp->annouce_pkt = XCALLOC(MTYPE_PIM_AUTORP_ANNOUNCE, sizeof(struct autorp_pkt_hdr) + sizeof(struct autorp_pkt_rp) + (UINT8_MAX * sizeof(struct autorp_pkt_grp)));
	autorp->annouce_pkt_sz = 0;

	hdr = (struct autorp_pkt_hdr *)autorp->annouce_pkt;
	autorp->annouce_pkt_sz += sizeof(struct autorp_pkt_hdr);

	hdr->version = AUTORP_VERSION;
	hdr->type = AUTORP_ANNOUNCEMENT_TYPE;
	hdr->holdtime = htons((uint16_t)holdtime);
	hdr->reserved = 0;
	hdr->rpcnt = 1; /* We will only ever pack 1 rp */

	rp = (struct autorp_pkt_rp *)(autorp->annouce_pkt + autorp->annouce_pkt_sz);
	autorp->annouce_pkt_sz += sizeof(struct autorp_pkt_rp);

	/* Since this is an in_addr, assume it's already the right byte order */
	rp->addr = autorp->cand_rp_addrsel.run_addr.s_addr;
	rp->pimver = PIM_V2;
	rp->reserved = 0;
	rp->grpcnt = 0; /* Start with 0 */

	if (is_default_prefix(&(autorp->cand_rp_grplist.grp))) {
		/* No group so pack from the prefix list */
		struct prefix_list *plist;
		struct prefix_list_entry *ple;

		plist = prefix_list_lookup(AFI_IP, autorp->cand_rp_grplist.plist);
		for (ple = plist->head; ple; ple = ple->next) {
			/* Only pack multicast groups */
			if (pim_addr_is_multicast(pim_addr_from_prefix(&ple->prefix))) {
				grp = (struct autorp_pkt_grp *)(autorp->annouce_pkt + autorp->annouce_pkt_sz);
				autorp->annouce_pkt_sz += sizeof(struct autorp_pkt_grp);

				grp->addr = ple->prefix.u.prefix4.s_addr;
				grp->masklen = ple->prefix.prefixlen;
				grp->negprefix = (ple->type == PREFIX_PERMIT ? 0 : 1);
				grp->reserved = 0;
				rp->grpcnt += 1;
			}
		}

		/* Return if prefix list had no multicast groups */
		if (rp->grpcnt == 0)
			return;
	} else {
		grp = (struct autorp_pkt_grp *)(autorp->annouce_pkt + autorp->annouce_pkt_sz);
		autorp->annouce_pkt_sz += sizeof(struct autorp_pkt_grp);

		/* Only one of group or prefix list should be defined */
		grp->addr = autorp->cand_rp_grplist.grp.u.prefix4.s_addr;
		grp->masklen = autorp->cand_rp_grplist.grp.prefixlen;
		grp->negprefix = 0;
		grp->reserved = 0;
		rp->grpcnt = 1;
	}

	/* Now we have a packet to send, so start the announcement timer */
	autorp_announcement_on(autorp);
}

void pim_autorp_prefix_list_update(struct pim_instance *pim, struct prefix_list *plist)
{
	struct pim_autorp *autorp;

	if (pim == NULL || plist == NULL)
		return;

	autorp = pim->autorp;
	if (autorp == NULL)
		return;

	if (autorp->cand_rp_grplist.plist == NULL || plist->name == NULL)
		return;

	/* Check the candidate RP prefix list, if it matches, rebuild the announcement packet */
	if (strmatch(autorp->cand_rp_grplist.plist, plist->name))
		pim_autorp_new_announcement(pim);
}

void pim_autorp_candidate_rp_apply(struct pim_instance *pim)
{
	/* Rebuild the announcement packet on any changes to candidate rp */
	pim_autorp_new_announcement(pim);
}

void pim_autorp_announce_scope(struct pim_instance *pim, uint8_t scope)
{
	struct pim_autorp *autorp = pim->autorp;

	scope = (scope == 0 ? DEFAULT_ANNOUNCE_SCOPE : scope);
	if (autorp->announce_scope != scope) {
		autorp->announce_scope = scope;
		pim_autorp_new_announcement(pim);
	}
}

void pim_autorp_announce_interval(struct pim_instance *pim, uint16_t interval)
{
	struct pim_autorp *autorp = pim->autorp;

	interval = (interval == 0 ? DEFAULT_ANNOUNCE_INTERVAL : interval);
	if (autorp->announce_interval != interval) {
		autorp->announce_interval = interval;
		pim_autorp_new_announcement(pim);
	}
}

void pim_autorp_announce_holdtime(struct pim_instance *pim, int32_t holdtime)
{
	struct pim_autorp *autorp = pim->autorp;

	if (autorp->announce_holdtime != holdtime) {
		autorp->announce_holdtime = holdtime;
		pim_autorp_new_announcement(pim);
	}
}

void pim_autorp_add_ifp(struct interface *ifp)
{
	/* Add a new interface for autorp
	 *   When autorp is enabled, we must join the autorp groups on all
	 *   pim/multicast interfaces. When autorp first starts, if finds all
	 *   current multicast interfaces and joins on them. If a new interface
	 *   comes up or is configured for multicast after autorp is running, then
	 *   this method will add it for autorp->
	 * This is called even when adding a new pim interface that is not yet
	 * active, so make sure the check, it'll call in again once the interface is up.
	 */
	struct pim_instance *pim;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) && pim_ifp &&
	    pim_ifp->pim_enable) {
		pim = pim_ifp->pim;
		if (pim && pim->autorp && pim->autorp->do_discovery) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Adding interface %s to AutoRP, joining AutoRP groups",
					   __func__, ifp->name);
			if (!pim_autorp_join_groups(ifp)) {
				zlog_err("Could not join AutoRP groups, errno=%d, %s",
					 errno, safe_strerror(errno));
			}
		}
	}
}

void pim_autorp_rm_ifp(struct interface *ifp)
{
	/* Remove interface for autorp
	 *   When an interface is no longer enabled for multicast, or at all, then
	 *   we should leave the AutoRP groups on this interface.
	 */
	struct pim_instance *pim;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE) && pim_ifp) {
		pim = pim_ifp->pim;
		if (pim && pim->autorp) {
			if (PIM_DEBUG_AUTORP)
				zlog_debug("%s: Removing interface %s from AutoRP, leaving AutoRP groups",
					   __func__, ifp->name);
			if (!pim_autorp_leave_groups(ifp)) {
				zlog_err("Could not leave AutoRP groups, errno=%d, %s",
					 errno, safe_strerror(errno));
			}
		}
	}
}

void pim_autorp_start_discovery(struct pim_instance *pim)
{
	struct interface *ifp;
	struct pim_autorp *autorp = pim->autorp;

	if (!autorp->do_discovery) {
		autorp->do_discovery = true;
		autorp_read_on(autorp);

		FOR_ALL_INTERFACES (autorp->pim->vrf, ifp) {
			pim_autorp_add_ifp(ifp);
		}

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP Discovery started", __func__);
	}
}

void pim_autorp_stop_discovery(struct pim_instance *pim)
{
	struct interface *ifp;
	struct pim_autorp *autorp = pim->autorp;

	if (autorp->do_discovery) {
		FOR_ALL_INTERFACES (autorp->pim->vrf, ifp) {
			pim_autorp_rm_ifp(ifp);
		}

		autorp->do_discovery = false;
		autorp_read_off(autorp);

		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP Discovery stopped", __func__);
	}
}

void pim_autorp_init(struct pim_instance *pim)
{
	struct pim_autorp *autorp;

	autorp = XCALLOC(MTYPE_PIM_AUTORP, sizeof(*autorp));
	autorp->pim = pim;
	autorp->sock = -1;
	autorp->read_event = NULL;
	autorp->announce_timer = NULL;
	autorp->do_discovery = false;
	pim_autorp_rp_init(&(autorp->discovery_rp_list));

	cand_addrsel_clear(&autorp->cand_rp_addrsel);
	autorp->cand_rp_grplist.grp.family = AF_INET;
	autorp->cand_rp_grplist.grp.prefixlen = 0;
	autorp->cand_rp_grplist.grp.u.prefix4.s_addr = 0;
	autorp->announce_scope = DEFAULT_ANNOUNCE_SCOPE;
	autorp->announce_interval = DEFAULT_ANNOUNCE_INTERVAL;
	autorp->announce_holdtime = DEFAULT_ANNOUNCE_HOLDTIME;

	if (!pim_autorp_socket_enable(autorp)) {
		zlog_err("%s: AutoRP failed to initialize", __func__);
		return;
	}

	pim->autorp = autorp;
	if (PIM_DEBUG_AUTORP)
		zlog_debug("%s: AutoRP Initialized", __func__);

	/* Start AutoRP discovery by default on startup */
	pim_autorp_start_discovery(pim);
}

void pim_autorp_finish(struct pim_instance *pim)
{
	struct pim_autorp *autorp = pim->autorp;

	autorp_read_off(autorp);
	pim_autorp_free(autorp);
	if (pim_autorp_socket_disable(autorp)) {
		if (PIM_DEBUG_AUTORP)
			zlog_debug("%s: AutoRP Finished", __func__);
	} else
		zlog_err("%s: AutoRP failed to finish", __func__);

	XFREE(MTYPE_PIM_AUTORP, pim->autorp);
}

int pim_autorp_config_write(struct pim_instance *pim, struct vty *vty)
{
	struct pim_autorp *autorp = pim->autorp;
	int writes = 0;

	if (!autorp->do_discovery) {
		vty_out(vty, " no autorp discovery\n");
		++writes;
	}

	if (autorp->announce_interval != DEFAULT_ANNOUNCE_INTERVAL || autorp->announce_scope != DEFAULT_ANNOUNCE_SCOPE || autorp->announce_holdtime != DEFAULT_ANNOUNCE_HOLDTIME) {
		vty_out(vty, " autorp announce");
		if (autorp->announce_interval != DEFAULT_ANNOUNCE_INTERVAL)
			vty_out(vty, " interval %u", autorp->announce_interval);
		if (autorp->announce_scope != DEFAULT_ANNOUNCE_SCOPE)
			vty_out(vty, " scope %u", autorp->announce_scope);
		if (autorp->announce_holdtime != DEFAULT_ANNOUNCE_HOLDTIME)
			vty_out(vty, " holdtime %u", autorp->announce_holdtime);
		vty_out(vty, "\n");
		++writes;
	}

	if (autorp->cand_rp_addrsel.cfg_enable) {
		vty_out(vty, " autorp announce source");
		switch (autorp->cand_rp_addrsel.cfg_mode) {
		case CAND_ADDR_LO:
			vty_out(vty, " loopback");
			break;
		case CAND_ADDR_ANY:
			vty_out(vty, " any");
			break;
		case CAND_ADDR_IFACE:
			vty_out(vty, " interface %s", autorp->cand_rp_addrsel.cfg_ifname);
			break;
		case CAND_ADDR_EXPLICIT:
			vty_out(vty, " address %pPA", &autorp->cand_rp_addrsel.cfg_addr);
			break;
		}
		if (!is_default_prefix(&(autorp->cand_rp_grplist.grp)))
			vty_out(vty, " %pFX", &(autorp->cand_rp_grplist.grp));
		else
			vty_out(vty, " group-list %s", autorp->cand_rp_grplist.plist);
		vty_out(vty, "\n");
		++writes;
	}

	return writes;
}

void pim_autorp_show_autorp(struct vty *vty, struct pim_instance *pim, json_object *json)
{
	struct pim_autorp *autorp = pim->autorp;
	struct ttable *tt = NULL;
	char *table = NULL;
	json_object *annouce_jobj;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "RP address|Group|Prefix-list");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);

	if (!is_default_prefix(&autorp->cand_rp_grplist.grp))
		ttable_add_row(tt, "%pI4|%pFX|%s", &(autorp->cand_rp_addrsel.run_addr), &autorp->cand_rp_grplist.grp, "-");
	else
		ttable_add_row(tt, "%pI4|%s|%s", &(autorp->cand_rp_addrsel.run_addr), "-", autorp->cand_rp_grplist.plist);

	if (json) {
		json_object_boolean_add(json, "discoveryEnabled", autorp->do_discovery);

		annouce_jobj = json_object_new_object();
		json_object_int_add(annouce_jobj, "scope", autorp->announce_scope);
		json_object_int_add(annouce_jobj, "interval", autorp->announce_interval);
		json_object_int_add(annouce_jobj, "holdtime", autorp->announce_holdtime);
		json_object_object_add(annouce_jobj, "rpList", ttable_json_with_json_text( tt, "sss", "rpAddress|group|prefixList"));
		json_object_object_add(json, "announce", annouce_jobj);
	} else {
		vty_out(vty, "AutoRP Discovery is %sabled\n", (autorp->do_discovery ? "en" : "dis"));
		vty_out(vty, "AutoRP Candidate RPs\n");
		vty_out(vty, "  interval %us, scope %u, holdtime %us\n", autorp->announce_interval, autorp->announce_scope, (autorp->announce_holdtime == DEFAULT_ANNOUNCE_HOLDTIME ? (autorp->announce_interval * 3) : autorp->announce_holdtime));
		vty_out(vty, "\n");
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP_TTABLE, table);
	}

	ttable_del(tt);
}
