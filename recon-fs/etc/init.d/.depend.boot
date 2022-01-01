TARGETS = console-setup alsa-utils fake-hwclock resolvconf mountkernfs.sh plymouth-log hostname.sh udev keyboard-setup cryptdisks cryptdisks-early checkroot.sh networking urandom hwclock.sh mountdevsubfs.sh checkfs.sh procps kmod mountall-bootclean.sh mountall.sh bootmisc.sh mountnfs-bootclean.sh mountnfs.sh checkroot-bootclean.sh
INTERACTIVE = console-setup udev keyboard-setup cryptdisks cryptdisks-early checkroot.sh checkfs.sh
udev: mountkernfs.sh
keyboard-setup: mountkernfs.sh udev
cryptdisks: checkroot.sh cryptdisks-early udev
cryptdisks-early: checkroot.sh udev
checkroot.sh: fake-hwclock hwclock.sh mountdevsubfs.sh hostname.sh keyboard-setup
networking: resolvconf mountkernfs.sh urandom procps
urandom: hwclock.sh
hwclock.sh: mountdevsubfs.sh
mountdevsubfs.sh: mountkernfs.sh udev
checkfs.sh: cryptdisks checkroot.sh
procps: mountkernfs.sh udev
kmod: checkroot.sh
mountall-bootclean.sh: mountall.sh
mountall.sh: checkfs.sh checkroot-bootclean.sh
bootmisc.sh: mountall-bootclean.sh udev mountnfs-bootclean.sh checkroot-bootclean.sh
mountnfs-bootclean.sh: mountnfs.sh
mountnfs.sh: networking
checkroot-bootclean.sh: checkroot.sh
