[![.github/workflows/kernel.yml](https://github.com/L4STeam/linux/workflows/bindeb-pkg/badge.svg)](https://github.com/L4STeam/linux/actions)
# Linux kernel tree with L4S patches

This linux kernel repository contains the various patches developed in the
context of the L4S experiment.

Namely:
- The dualQ coupled AQM (see branch sch_dualpi2, as well as the
[iproute2 repository](https://github.com/L4STeam/iproute2)
- An implementation of Accurate ECN (see branch AccECN-tcphdr)
- Various enhancements to DCTCP
- The base implementation of TCP Prague (see branch tcp_prague)

## This branch (testing)

This branch accumulates all patches into a single kernel tree, in order to ease
up testing.

You can grab a pre-built debian archive of the kernel image and headers through
the latest [actions artifacts](https://github.com/L4STeam/linux/actions).

## Compilation

Compile it as any kernel, enabling the dualpi2 AQM and TCP Prague in the config.

Assuming you compile this on a similar machine that where you intend to run the
kernel (e.g., architecture, distribution, ...):
```bash
# Try to use existing kernel config
if [ -f /proc/config.gz ]; then
    zcat proc/config.gz > .config
    make olddefconfig
else if [ -f "/boot/config-$(uname -r)" ]; then
    cp "/boot/config-$(uname -r)" .config
    make olddefconfig
else
    make defconfig
fi

# Enable TCP Prague and dualpi2
scripts/config -m TCP_CONG_PRAGUE
scripts/config -m NET_SCH_DUALPI2

# Build the kernel
make -j$(nproc)
# Alternatively, you can generate *.deb with
# BUILD_NUMBER=${BUILD_NUMBER:-1} make \
#	-j$(nproc) bindeb-pkg \
#	LOCALVERSION=-prague-${BUILD_NUMBER} \
#	KDEB_PKGVERSION=1
# see the output of `make help` to generate rpms/...

# Install it on the current system if applicable
make install
make modules_install
```

## Performing experiments

While dualpi2 can work with DCTCP, DCTCP suffers from a few unfortunate
interactions with GSO/pacing/..., resulting in under-utilization. As a result,
we advice you to use tcp_prague which currently has
basic fixes to those limitations. Note that this might still under-perform in
heavyly virtualized settings, as scheduling becomes less reliable.

```bash
sysctl -w net.ipv4.tcp_congestion_control=prague
# Enable Accurate ECN
sysctl -w net.ipv4.tcp_ecn=3
```

Note that, at the moment, Accurate ECN **must** be enabled on both ends of a
connection in order to use prague as congestion control. Unlike DCTCP, it is
sufficient to only use prague on the "bulk sender".
