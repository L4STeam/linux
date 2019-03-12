/* TCP Prague congestion control.
 *
 * This congestion-control, part of the L4S architecture, achieves low loss,
 * low latency and scalable throughput when used in combination with AQMs such
 * as DualPI2, CurvyRED, or even fq_codel with a low ce_threshold for the
 * L4S flows.
 *
 * This is heavily based on DCTCP, albeit aimed to be used over the public
 * internet over paths supporting the L4S codepoint---ECT(1), and thus
 * implements the safety requirements listed in Appendix A of:
 * https://tools.ietf.org/html/draft-ietf-tsvwg-ecn-l4s-id-06#page-23
 *
 * Authors:
 *	Olivier Tilmans <olivier.tilmans@nokia-bell-labs.com>
 *	Koen de Schepper <koen.de_schepper@nokia-bell-labs.com>
 *	Bob briscoe <research@bobbriscoe.net>
 *
 * DCTCP Authors:
 *
 *	Daniel Borkmann <dborkman@redhat.com>
 *	Florian Westphal <fw@strlen.de>
 *	Glenn Judd <glenn.judd@morganstanley.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#define pr_fmt(fmt) "TCP-Prague: " fmt

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include "tcp_dctcp.h"

#define PRAGUE_ALPHA_BITS	31
#define PRAGUE_MAX_ALPHA	(1U << PRAGUE_ALPHA_BITS)

struct prague {
	u64 prague_alpha;	/* This holds alpha << prague_shift_g */
	u32 delivered;
	u32 delivered_ce;
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 next_seq;
	u32 loss_cwnd;
	bool was_ce;
};

static unsigned int prague_shift_g __read_mostly = 4; /* g = 1/2^4 */
static unsigned int prague_alpha_on_init __read_mostly = PRAGUE_MAX_ALPHA;
static int prague_ect __read_mostly = 1;
static int prague_ecn_plus_plus __read_mostly = 1;
static char *prague_ca_fallback __read_mostly = "cubic";

MODULE_PARM_DESC(prague_shift_g, "gain parameter for alpha EWMA");
module_param(prague_shift_g, uint, 0644);

MODULE_PARM_DESC(prague_alpha_on_init, "initial alpha value");
module_param(prague_alpha_on_init, uint, 0644);

MODULE_PARM_DESC(prague_ect, "send packet with ECT(prague_ect)");
/* We currently do not allow this to change through sysfs */
module_param(prague_ect, int, 0444);

MODULE_PARM_DESC(prague_ecn_plus_plus, "set ECT on control packets");
module_param(prague_ecn_plus_plus, int, 0444);

MODULE_PARM_DESC(prague_ca_fallback, "CC to use if AccECN is not supported");
module_param(prague_ca_fallback, charp, 0644);


static struct prague *prague_ca(struct sock *sk)
{
	return (struct prague*)inet_csk_ca(sk);
}

static void prague_reset(const struct tcp_sock *tp, struct prague *ca)
{
	ca->next_seq = tp->snd_nxt;
	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
	ca->delivered_ce = tp->delivered_ce;
	ca->delivered = tp->delivered;
	ca->was_ce = false;
}

static void prague_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* We forced the use of ECT(x), disable this before switching CC */
	INET_ECN_dontxmit(sk);
	/* TODO(otilmans) if we allow that param to be 0644 then we'll
	 * need to deal with that here and not unconditionally reset
	 * the flag (e.g., could have been set by bpf prog)
	 */
	tp->ecn_flags &= ~TCP_ECN_ECT_1;
}

static void prague_fallback_to_ca(struct sock *sk)
{
	prague_release(sk);
	tcp_set_congestion_control(sk, prague_ca_fallback, true, true);
	switch(sk->sk_family) {
	case AF_INET:
		pr_info("%pI4:%u-%pI4:%u Falling back to %s\n",
			&sk->sk_rcv_saddr, ntohs(inet_sk(sk)->inet_sport),
			&sk->sk_daddr, ntohs(sk->sk_dport),
			prague_ca_fallback);
		break;
	case AF_INET6:
		pr_info("[%pI6c]:%u-[%pI6c]:%u Falling back to %s\n",
			&sk->sk_v6_rcv_saddr.s6_addr,
			ntohs(inet_sk(sk)->inet_sport),
			&sk->sk_v6_daddr.s6_addr, ntohs(sk->sk_dport),
			prague_ca_fallback);
		break;
	default:
		break;
	}
}

static void prague_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if ((tp->ecn_flags & TCP_ACCECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE) ||
	    sock_net(sk)->ipv4.sysctl_tcp_force_peer_unreliable_ece) {
		struct prague *ca = prague_ca(sk);

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;
		ca->prague_alpha =
			((u64)min(prague_alpha_on_init, PRAGUE_MAX_ALPHA))
			<< prague_shift_g;
		ca->loss_cwnd = 0;

		if (prague_ect)
			tp->ecn_flags |= TCP_ECN_ECT_1;

		prague_reset(tp, ca);
		return;
	}
	/* Cannot use Prague without AccECN or the unreliable fallback */
	prague_fallback_to_ca(sk);
}

static u32 prague_ssthresh(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 reduction;

	ca->loss_cwnd = tp->snd_cwnd;
	reduction = ((ca->prague_alpha >> prague_shift_g) * tp->snd_cwnd
		     /* Unbias the rouding by adding 1/2 */
		     + PRAGUE_MAX_ALPHA) >> (PRAGUE_ALPHA_BITS  + 1U);
	return max(tp->snd_cwnd - (u32)reduction, 2U);
}

static void prague_update_alpha(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct prague *ca = prague_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = tp->mss_cache;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;

		if (tp->ecn_flags & TCP_ACCECN_OK) {
			const u32 d_ce = tp->delivered_ce - ca->delivered_ce;
			const u32 d_packets = tp->delivered - ca->delivered;
			if (d_packets && d_ce) {
				/* TODO(otilmans) figure out a way to get rid of the
				 * following division in the TCP fast path.
				 */
				const u32 avg_psize = acked_bytes / d_packets;

				ca->acked_bytes_ecn += d_ce * avg_psize;
			}
		}
	}
	ca->delivered = tp->delivered;
	ca->delivered_ce = tp->delivered_ce;

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		u64 bytes_ecn = ca->acked_bytes_ecn;
		u64 alpha = ca->prague_alpha;

		/* alpha = (1 - g) * alpha + g * F
		*
		* We use dctcp_shift_g = G = 1 / g
		* and store dctcp_alpha = A = alpha * G
		*
		* The EWMA then becomes A = A * (1 - 1/G) + F
		*
		* We first compute F, the fraction of ecn bytes.
		*/
		if (bytes_ecn) {
			/* bytes_ecn has to be 64b to avoid overfow as alpha's
			 * resolution increases.
			 */
			bytes_ecn <<= PRAGUE_ALPHA_BITS;
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));
		}
		alpha = alpha - (alpha >> prague_shift_g) + bytes_ecn;
		/* prague_alpha can be read from prague_get_info() without
		 * synchro, so we ask compiler to not use prague_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->prague_alpha, alpha);
		prague_reset(tp, ca);
	}
}

static void prague_react_to_loss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	prague_ca(sk)->loss_cwnd = tp->snd_cwnd;
	/* Stay fair with reno/cubic (RFC-style) */
	tp->snd_ssthresh = max(tp->snd_cwnd >> 1U, 2U);
}

static void prague_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Recovery
	    && new_state != inet_csk(sk)->icsk_ca_state)
		/* React to the first fast retransmit of this window */
		prague_react_to_loss(sk);
}

static void prague_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch(ev) {
	case CA_EVENT_ECN_IS_CE:
		prague_ca(sk)->was_ce = true;
		break;
	case CA_EVENT_ECN_NO_CE:
		if (prague_ca(sk)->was_ce)
			/* Immediately ACK a trail of CE packets */
			inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_NOW;
		prague_ca(sk)->was_ce = false;
		break;
	case CA_EVENT_LOSS:
		/* React to a RTO if no other loss-related events happened
		 * during this window.
		 */
		prague_react_to_loss(sk);
		break;
	default:
		/* Ignore everything else */
		break;
	}
}

static size_t prague_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct prague *ca = inet_csk_ca(sk);

	if (ext & (1 << (INET_DIAG_PRAGUEINFO - 1))) {
		memset(&info->prague, 0, sizeof(info->prague));
		info->prague.prague_alpha =
			ca->prague_alpha >> prague_shift_g;
		info->prague.prague_ab_ecn = ca->acked_bytes_ecn;
		info->prague.prague_ab_tot = ca->acked_bytes_total;

		*attr = INET_DIAG_PRAGUEINFO;
		return sizeof(info->prague);
	}
	return 0;
}

static u32 prague_cwnd_undo(struct sock *sk)
{
	const struct prague *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static struct tcp_congestion_ops prague __read_mostly = {
	.init		= prague_init,
	.release	= prague_release,
	.in_ack_event   = prague_update_alpha,
	.cwnd_event	= prague_cwnd_event,
	.ssthresh	= prague_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= prague_cwnd_undo,
	.set_state	= prague_state,
	.get_info	= prague_get_info,
	.flags		= TCP_CONG_NEEDS_ECN | TCP_CONG_NON_RESTRICTED,
	.owner		= THIS_MODULE,
	.name		= "prague",
};

static int __init prague_register(void)
{
	BUILD_BUG_ON(sizeof(struct prague) > ICSK_CA_PRIV_SIZE);

	if (prague_ect)
		prague.flags |= TCP_CONG_WANTS_ECT_1;
	if (!prague_ecn_plus_plus)
		prague.flags &= ~TCP_CONG_NEEDS_ECN;

	return tcp_register_congestion_control(&prague);
}

static void __exit prague_unregister(void)
{
	tcp_unregister_congestion_control(&prague);
}

module_init(prague_register);
module_exit(prague_unregister);

MODULE_AUTHOR("Olivier Tilmans <olivier.tilmans@nokia-bell-labs.com>");
MODULE_AUTHOR("Koen de Schepper <koen.de_schepper@nokia-bell-labs.com>");
MODULE_AUTHOR("Bob briscoe <research@bobbriscoe.net>");

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("TCP Prague");
