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
#include <linux/inet.h>

#define PRAGUE_ALPHA_BITS	31
#define PRAGUE_MAX_ALPHA	((u64)(1U << PRAGUE_ALPHA_BITS))

static struct tcp_congestion_ops prague_reno;

struct prague {
	u64 upscaled_alpha;
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 prior_rcv_nxt;
	u32 next_seq;
	u32 loss_cwnd;
	u32 max_tso_burst;
	bool was_ce;
	bool saw_ce;
};

static u32 prague_shift_g __read_mostly = 4; /* g = 1/2^4 */
static int prague_ect __read_mostly = 1;
static int prague_ecn_plus_plus __read_mostly = 1;
static u32 prague_burst_usec __read_mostly = 250; /* .25ms */

MODULE_PARM_DESC(prague_shift_g, "gain parameter for alpha EWMA");
module_param(prague_shift_g, uint, 0644);

MODULE_PARM_DESC(prague_burst_usec, "maximal TSO burst duration");
module_param(prague_burst_usec, uint, 0644);

MODULE_PARM_DESC(prague_ect, "send packet with ECT(prague_ect)");
/* We currently do not allow this to change through sysfs */
module_param(prague_ect, int, 0444);

MODULE_PARM_DESC(prague_ecn_plus_plus, "set ECT on control packets");
module_param(prague_ecn_plus_plus, int, 0444);


static struct prague *prague_ca(struct sock *sk)
{
	return (struct prague*)inet_csk_ca(sk);
}

static u32 prague_max_tso_seg(struct sock *sk)
{
	return prague_ca(sk)->max_tso_burst;
}

static bool prague_rtt_complete(struct sock *sk)
{
	/* At the moment, we detect expired RTT using cwnd completion */
	return !before(tcp_sk(sk)->snd_una, prague_ca(sk)->next_seq);
}

static void __prague_connection_id(struct sock *sk, char *str, size_t len)
{
	u16 dport = ntohs(inet_sk(sk)->inet_dport),
	    sport = ntohs(inet_sk(sk)->inet_sport);
	if (sk->sk_family == AF_INET)
		snprintf(str, len, "%pI4:%u-%pI4:%u", &sk->sk_rcv_saddr, sport,
			&sk->sk_daddr, dport);
	else if (sk->sk_family == AF_INET6)
		snprintf(str, len, "[%pI6c]:%u-[%pI6c]:%u",
			 &sk->sk_v6_rcv_saddr, sport, &sk->sk_v6_daddr, dport);
}
#define LOG(sk, fmt, ...) do { \
	char __tmp[2 * (INET6_ADDRSTRLEN + 9) + 1] = {0}; \
	__prague_connection_id(sk, __tmp, sizeof(__tmp)); \
	pr_info("Prague %s " fmt, __tmp, ##__VA_ARGS__); \
} while (0)

static void prague_reset(const struct tcp_sock *tp, struct prague *ca)
{
	ca->next_seq = tp->snd_nxt;
	ca->old_delivered_ce = tp->delivered_ce;
	ca->old_delivered = tp->delivered;
	ca->was_ce = false;
}

static u32 prague_ssthresh(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 reduction;

	ca->loss_cwnd = tp->snd_cwnd;
	reduction = ((ca->upscaled_alpha >> prague_shift_g) * tp->snd_cwnd
		     /* Unbias the rounding by adding 1/2 */
		     + PRAGUE_MAX_ALPHA) >> (PRAGUE_ALPHA_BITS  + 1U);
	return max(tp->snd_cwnd - (u32)reduction, 2U);
}

static void prague_update_pacing_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u64 max_burst, rate;
	u32 max_inflight;

	max_inflight = max(tp->snd_cwnd, tp->packets_out);

	rate = (u64)tp->mss_cache * (USEC_PER_SEC << 3) * max_inflight;
	if (likely(tp->srtt_us))
		do_div(rate, tp->srtt_us);

	max_burst = div_u64(rate * prague_burst_usec,
			    tp->mss_cache * USEC_PER_SEC);
	max_burst = max_t(u32, 1, max_burst);
	WRITE_ONCE(prague_ca(sk)->max_tso_burst, max_burst);

	if (tp->snd_cwnd < tp->snd_ssthresh / 2)
		/* 200% for slowstart */
		rate *= 2 ;
	else if (tp->packets_out < tp->snd_cwnd)
		/* Scale pacing rate based on the number of consecutive segments
		 * that can be sent, i.e., rate is 200% for high BDPs
		 * that are perfectly ACK-paced (i.e., where packets_out is
		 * almost max_inflight), but decrease to 100% if a full
		 * RTT is aggregated into a single ACK or if we have more in
		 * flight data than our cwnd allows.
		 */
		rate += rate * (1 + tp->packets_out) / max_inflight;
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	WRITE_ONCE(sk->sk_pacing_rate, rate);
}

static void prague_rtt_expired(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 ecn_segs, alpha;

	/* Do not update alpha before we have proof that there's an AQM on
	 * the path.
	 */
	if (unlikely(!ca->saw_ce))
		goto reset;

	alpha = ca->upscaled_alpha;
	ecn_segs = tp->delivered_ce - ca->old_delivered_ce;
	/* We diverge from the original EWMA, i.e.,
	 * alpha = (1 - g) * alpha + g * F
	 * by working with (and storing)
	 * upscaled_alpha = alpha * (1/g) [recall that 0<g<1]
	 *
	 * This enables to carry alpha's residual value to the next EWMA round.
	 *
	 * We first compute F, the fraction of ecn segments.
	 */
	if (ecn_segs) {
		u32 acked_segs = tp->delivered - ca->old_delivered;

		ecn_segs <<= PRAGUE_ALPHA_BITS;
		do_div(ecn_segs, max(1U, acked_segs));
	}
	alpha = alpha - (alpha >> prague_shift_g) + ecn_segs;

	WRITE_ONCE(ca->upscaled_alpha, alpha);

reset:
	prague_reset(tp, ca);
}

static void prague_update_window(struct sock *sk,
				 const struct rate_sample *rs)
{
	/* Do not increase cwnd for ACKs indicating congestion */
	if (rs->is_ece) {
		prague_ca(sk)->saw_ce = true;
		return;
	}

	tcp_reno_cong_avoid(sk, 0, rs->acked_sacked);
}

static void prague_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	prague_update_window(sk, rs);
	if (prague_rtt_complete(sk))
		prague_rtt_expired(sk);

	prague_update_pacing_rate(sk);
}

static void prague_react_to_loss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	prague_ca(sk)->loss_cwnd = tp->snd_cwnd;
	/* Stay fair with reno (RFC-style) */
	tp->snd_ssthresh = max(tp->snd_cwnd >> 1U, 2U);
}

static void prague_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (new_state == inet_csk(sk)->icsk_ca_state)
		return;

	switch (new_state) {
		case TCP_CA_Recovery:
			prague_react_to_loss(sk);
			break;
		case TCP_CA_CWR:
			tp->snd_cwnd = prague_ssthresh(sk);
			tp->snd_ssthresh = tp->snd_cwnd;
			break;
		default:
			break;
	}
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

static u32 prague_cwnd_undo(struct sock *sk)
{
	const struct prague *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static size_t prague_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct prague *ca = prague_ca(sk);

	if (ext & (1 << (INET_DIAG_PRAGUEINFO - 1))) {
		memset(&info->prague, 0, sizeof(info->prague));
		info->prague.prague_alpha =
			ca->upscaled_alpha >> prague_shift_g;
		info->prague.prague_max_burst = ca->max_tso_burst;

		*attr = INET_DIAG_PRAGUEINFO;
		return sizeof(info->prague);
	}
	return 0;
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
	LOG(sk, "Releasing: delivered_ce=%u, received_ce=%u, "
	    "received_ce_tx: %u\n", tp->delivered_ce, tp->received_ce,
	    tp->received_ce_tx);
}

static void prague_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* We're stuck in TCP_ACCECN_PENDING before the 3rd ACK */
	if (tcp_ecn_ok(tp) ||
	    (sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)) {
		struct prague *ca = prague_ca(sk);
		struct tcp_sock *tp = tcp_sk(sk);

		ca->prior_rcv_nxt = tp->rcv_nxt;
		ca->upscaled_alpha = PRAGUE_MAX_ALPHA << prague_shift_g;
		ca->loss_cwnd = 0;
		ca->saw_ce = tp->delivered_ce != TCP_ACCECN_CEP_INIT;
		/* Conservatively start with a very low TSO limit */
		ca->max_tso_burst = 1;

		if (prague_ect)
			tp->ecn_flags |= TCP_ECN_ECT_1;

		cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE,
			SK_PACING_NEEDED);

		prague_reset(tp, ca);
		return;
	}
	/* Cannot use Prague without AccECN
	 * TODO(otilmans) If TCP_ECN_OK, we can trick the receiver to echo few
	 * ECEs per CE received by setting CWR at most once every two segments.
	 * This is however quite sensitive to ACK thinning...
	 */
	prague_release(sk);
	LOG(sk, "Switching back to reno fallback\n");
	inet_csk(sk)->icsk_ca_ops = &prague_reno;
}

static struct tcp_congestion_ops prague __read_mostly = {
	.init		= prague_init,
	.release	= prague_release,
	.cong_control	= prague_cong_control,
	.cwnd_event	= prague_cwnd_event,
	.ssthresh	= prague_ssthresh,
	.undo_cwnd	= prague_cwnd_undo,
	.set_state	= prague_state,
	.get_info	= prague_get_info,
	.max_tso_segs	= prague_max_tso_seg,
	.flags		= TCP_CONG_NEEDS_ECN | TCP_CONG_NEEDS_ACCECN |
		TCP_CONG_NON_RESTRICTED,
	.owner		= THIS_MODULE,
	.name		= "prague",
};

static struct tcp_congestion_ops prague_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= prague_get_info,
	.owner		= THIS_MODULE,
	.name		= "prague-reno",
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
