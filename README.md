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
up testing. For book-keeping purposes, branches named legacy-testing-ddmmyy
point to older version, which were rebased against net-next.

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
