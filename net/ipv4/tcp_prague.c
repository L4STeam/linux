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
#define PRAGUE_MAX_ALPHA	(1U << PRAGUE_ALPHA_BITS)

static struct tcp_congestion_ops prague_reno;

struct prague {
	u64 upscaled_alpha;
	u32 delivered;
	u32 delivered_ce;
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 next_seq;
	u32 loss_cwnd;
	u32 max_tso_burst;
	bool was_ce;
};

static unsigned int prague_shift_g __read_mostly = 4; /* g = 1/2^4 */
static int prague_ect __read_mostly = 1;
static int prague_ecn_plus_plus __read_mostly = 1;

MODULE_PARM_DESC(prague_shift_g, "gain parameter for alpha EWMA");
module_param(prague_shift_g, uint, 0644);

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
	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
	ca->delivered_ce = tp->delivered_ce;
	ca->delivered = tp->delivered;
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

	rate = (u64)tp->mss_cache * (USEC_PER_SEC << 3);
	if (tp->snd_cwnd < tp->snd_ssthresh / 2)
		rate *= 2 * max(tp->snd_cwnd, tp->packets_out);
	else
		/* Spread over the full RTT, with enough room for AI */
		rate *= max(tp->snd_cwnd, tp->packets_out) + 2;

	if (likely(tp->srtt_us))
		do_div(rate, tp->srtt_us);


	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	/* Allow TSO bursts of at most 1ms */
	max_burst = rate;
	do_div(max_burst, (tp->mss_cache * MSEC_PER_SEC));
	prague_ca(sk)->max_tso_burst = max_t(u32, max_burst, 1);

	WRITE_ONCE(sk->sk_pacing_rate, rate);
}

static void prague_rtt_expired(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 bytes_ecn, alpha;

	bytes_ecn = ca->acked_bytes_ecn;
	alpha = ca->upscaled_alpha;
	/* We diverge from the original EWMA, i.e.,
	 * alpha = (1 - g) * alpha + g * F
	 * by working with (and storing)
	 * upscaled_alpha = alpha * (1/g) [recall that 0<g<1]
	 * As a result, the EWMA then becomes
	 * upscaled_alpha = upscaled_alpha * (1/g - 1) + F.
	 *
	 * This enables to carry alpha's residual value to the next EWMA round.
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

	WRITE_ONCE(ca->upscaled_alpha, alpha);

	prague_reset(tp, ca);
	if (bytes_ecn) {
		tp->snd_cwnd = prague_ssthresh(sk);
		tp->snd_ssthresh = tp->snd_cwnd;
	}
}

static void prague_update_window(struct sock *sk,
				 const struct rate_sample *rs)
{
	/* Do not increase cwnd for ACKs indicating congestion */
	if (rs->is_ece)
		return;

	tcp_reno_cong_avoid(sk, 0, rs->acked_sacked);
}

static void prague_update_ce_stats(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct prague *ca = prague_ca(sk);
	u32 acked_bytes;

	acked_bytes = tp->snd_una - ca->prior_snd_una;
	if (acked_bytes) {
		u32 d_ce = tp->delivered_ce - ca->delivered_ce;
		u32 d_packets = tp->delivered - ca->delivered;

		if (d_packets && d_ce) {
			u32 avg_psize = acked_bytes / d_packets;

			ca->acked_bytes_ecn += d_ce * avg_psize;
		}
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;
	}
	ca->delivered = tp->delivered;
	ca->delivered_ce = tp->delivered_ce;
}

static void prague_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	prague_update_ce_stats(sk);
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
		info->prague.prague_ab_ecn = ca->acked_bytes_ecn;
		info->prague.prague_ab_tot = ca->acked_bytes_total;

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

	if ((tp->ecn_flags & TCP_ACCECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {
		struct prague *ca = prague_ca(sk);

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;
		ca->upscaled_alpha = 0;
		ca->loss_cwnd = 0;
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
	.flags		= TCP_CONG_NEEDS_ECN | TCP_CONG_NON_RESTRICTED,
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
