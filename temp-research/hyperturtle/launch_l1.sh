#!/bin/bash

CUR_USR=$USER

if [ "$EUID" -eq 0 ]
then
    CUR_USR=$SUDO_USER
fi

USAGE="Usage: `basename $0` -i IMAGE_FILE [-k BZIMAGE] [-b] [-g] [-c <num_cpus>] [-m <mem>] [-e <seed_iso>]
where:
    -b              run with 2MiB huge pages
    -g              run with 1GiB huge pages
    -c <num_cpus>   specify num cpus
    -m <mem>        memory in GiB
    -e <seed_iso>   attach a cloud-init seed ISO (optional)"

MEM_SIZE=16
NUM_CPUS=4

# Opts
OPT_HUGE=0
EPT_CPU_FLAG=""
IMAGE=
SEED_ISO=""
PASSTHROUGH_DEVS=0
N_PASSTHROUGH_DEVICES=0
BZIMAGE=
KERNEL=
REDIRECT="mon:stdio"
SSH_PORT=2222
QMP_PORT=4444
SSH_FORWARD=2223
GDB_PORT=1234

# --- CLOUDLAB FIXES: Absolute paths for reproducibility ---
BASE_DIR="/work/hyperturtle"
QEMU_DIR="$BASE_DIR/hyperturtle-qemu/build"
SHARED_DIR_PATH="$BASE_DIR"
GUEST_IP="172.19.0.2"
IDLE_POLL="idle=poll"
PCI_ROOT_PORT=

# --- CLOUDLAB FIX: Added 'G:' and 'e:' to getopts string ---
while getopts dghbm:c:i:k:s:o:f:q:S:H:r:Q:P:p:G:e: opt; do
    case $opt in
        h) printf "$USAGE\n" >&2; exit 0 ;;
        b) OPT_HUGE=1 ;;
        g) OPT_HUGE=2 ;;
        c) NUM_CPUS=$((${OPTARG})) ;;
        m) MEM_SIZE=$((${OPTARG})) ;;
        d) IDLE_POLL="" ;;
        i) IMAGE=$OPTARG ;;
        k) BZIMAGE=$OPTARG ;;
        s) SCRIPT=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        f) SHARED_DIR_PATH=$OPTARG ;;
        q) QMP_PORT=$OPTARG ;;
        S) SSH_PORT=$OPTARG ;;
        H) SSH_FORWARD=$OPTARG ;;
        r) REDIRECT=$OPTARG ;;
        G) GDB_PORT=$OPTARG ;;
        Q) QEMU_DIR=$OPTARG ;;
        P) PASSTHROUGH_DEVS=$OPTARG ;;
        p) PREALLOC=$OPTARG ;;
        e) SEED_ISO=$OPTARG ;;
        \?) printf "$USAGE\n" >&2; exit 1 ;;
    esac
done

if [ -z $IMAGE ]; then
    echo "Please supply image: -i <my-image.img>"
    exit 1
fi

if [ ! -z $BZIMAGE ]; then
    KERNEL="-kernel $BZIMAGE"
    APPEND=('-append' "root=/dev/vda1 rw nokaslr norandmaps console=ttyS0 earlyprintk=serial,ttyS0 ignore_loglevel printk_delay=0 systemd.unified_cgroup_hierarchy=1 nopku nokaslr noibrs noibpb nospectre_v1 nospectre_v2 no_spectre_v2_user no_stf_barrier l1tf=off mds=off tsx=off tsx_async_abort=off intel_iommu=on transparent_hugepages=never mitigations=off nopti $IDLE_POLL isolcpus=1-2 ")
fi

if [ ! -z $SCRIPT ]; then
    APPEND+=(" < $SCRIPT")
fi

if [ ! -z $OUTPUT_FILE ]; then
    APPEND+=(" > $OUTPUT_FILE " " 2> $OUTPUT_FILE ")
fi

if [ -z "$is_virtualized" ]; then
    export is_virtualized=$(sudo dmesg | grep "Hypervisor detected" | wc -l)
fi

# --- CLOUDLAB FIX: Removed the buggy unconditional PREALLOC='off' overwrite ---
if [ -z "$PREALLOC" ]; then
    PREALLOC='off'
    if [ $is_virtualized -eq "0" ]; then
        PREALLOC='on'
    fi
fi

# Init for Qemu
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null
MEMORY="-object memory-backend-ram,size=${MEM_SIZE}G,merge=off,prealloc=$PREALLOC,id=m0"

# Free old huge pages if there are any
echo 0 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages > /dev/null
echo 0 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages > /dev/null

sudo umount /hugepages 2>/dev/null

PLE_GAP=$(cat /sys/module/kvm_intel/parameters/ple_gap 2>/dev/null)

if [ "$PLE_GAP" == "0" ]; then
    echo "ple_gap is already set to zero"
else
    sudo rmmod kvm_intel 2>/dev/null
    sudo modprobe kvm_intel ple_gap=0
fi

sudo rmmod vhost_net 2>/dev/null
sudo modprobe vhost_net experimental_zcopytx=1

if (( $OPT_HUGE != 0 )); then
    MEMORY="-object memory-backend-file,size=${MEM_SIZE}G,merge=off,mem-path=/hugepages,prealloc=on,id=m0"
    sudo mkdir -p /hugepages
    if (( $OPT_HUGE == 2 )); then
        echo "run huge memory 1G"
        NUM_HUGE=$((${MEM_SIZE}))
        echo $NUM_HUGE | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages > /dev/null
        sudo mount -t hugetlbfs -o pagesize=1G none /hugepages
    else
        echo "run huge memory 2M"
        NUM_HUGE=$(((${MEM_SIZE} * 1024)/2))
        echo $NUM_HUGE | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages > /dev/null
        sudo mount -t hugetlbfs -o pagesize=2M none /hugepages
    fi
    sudo chown -R $CUR_USR:$CUR_USR /hugepages
fi

# --- CLOUDLAB FIX: Proper Networking Logic ---
# If Passthrough is 0, we FORCE the user network stack so SSH works out of the box.
# If Passthrough > 0, we use the author's advanced TAP/Bridge logic.

if [ "$PASSTHROUGH_DEVS" -eq "0" ]; then
    echo "[*] Running with standard User Networking (Port 2222 -> 22)"
    NET="-netdev user,id=net0,hostfwd=tcp:0.0.0.0:${SSH_PORT}-:22 -device virtio-net-pci,netdev=net0"
else
    echo "[*] Running with Advanced Networking (Passthrough/TAP)"

    for ((i = 0; i < 16; i++)); do sudo cpufreq-set -c $i -d 2.1GHz -u 2.1GHz 2>/dev/null; done

    if [ $is_virtualized -eq "0" ]; then
        vIOMMU="-device intel-iommu,intremap=on,device-iotlb=true,caching-mode=on"
        N_PASSTHROUGH_DEVICES=$(( $PASSTHROUGH_DEVS + 1 ))
        for ((i = 1; i < $N_PASSTHROUGH_DEVICES; i++)); do
            if ! ifconfig | grep -q "tap$i"; then sudo ip tuntap add dev tap$i mode tap && sudo brctl addif br0 tap$i && sudo ifconfig tap$i up; fi
            PCI_ROOT_PORT="$PCI_ROOT_PORT -device pcie-root-port,id=rp$i,chassis=$i,bus=pcie.0,slot=$i"
            NET="$NET -device virtio-net-pci,netdev=net$i,disable-legacy=on,disable-modern=off,bus=rp$i,mrg_rxbuf=on,rx_queue_size=1024,tx_queue_size=1024,iommu_platform=on,ats=on,multifunction=on -netdev tap,id=net$i,ifname=tap$i,script=no,downscript=no,br=br0,poll-us=1000"
        done

        # Base tap devices for bare metal
        NET="$NET -device virtio-net-pci,netdev=net0,mrg_rxbuf=on,rx_queue_size=1024,tx_queue_size=1024,disable-legacy=on,disable-modern=off,multifunction=on -netdev tap,id=net0,vhost=on,ifname=tap0,script=no,downscript=no,br=br0,poll-us=0"
        if ! ifconfig | grep -q "tap0"; then sudo ip tuntap add dev tap0 mode tap && sudo brctl addif br0 tap0 && sudo ifconfig tap0 up; fi

        NET="$NET -device virtio-net-pci,netdev=net20,mrg_rxbuf=on,rx_queue_size=1024,tx_queue_size=1024,disable-legacy=on,disable-modern=off,multifunction=on,iommu_platform=on,ats=on -netdev tap,id=net20,ifname=tap20,script=no,downscript=no,br=br0,poll-us=1000,sndbuf=10000"
        if ! ifconfig | grep -q "tap20"; then sudo ip tuntap add dev tap20 mode tap && sudo brctl addif br0 tap20 && sudo ifconfig tap20 up; fi
    elif [ $is_virtualized -eq "1" ]; then
        sudo modprobe -v vfio-pci
        sudo modprobe -v vfio_iommu
        sudo driverctl set-override 0$PASSTHROUGH_DEVS:00.0 vfio-pci
        BDF_V=`lspci | grep 0$PASSTHROUGH_DEVS:00.0 | tail -n 1 | awk '{ print $1 }'`
        BDF_V=0000:$BDF_V
        NET="-device vfio-pci,host=$BDF_V,id=net2 -nic none"
    fi
    # CLOUDLAB: Add user-mode SSH alongside TAP networking
    NET="-netdev user,id=netssh,hostfwd=tcp:0.0.0.0:${SSH_PORT}-:22 -device virtio-net-pci,netdev=netssh $NET"
fi

PCI_HYPERUPCALL_BRIDGES="
-device pci-bridge,id=hp0,chassis_nr=1
-device pci-bridge,id=hp1,chassis_nr=2
-device pci-bridge,id=hp2,chassis_nr=3
-device pci-bridge,id=hp3,chassis_nr=4
-device pci-bridge,id=hp4,chassis_nr=5
-device pci-bridge,id=hp5,chassis_nr=6
-device pci-bridge,id=hp6,chassis_nr=7
-device pci-bridge,id=hp7,chassis_nr=8
"

QMP="-qmp tcp:localhost:${QMP_PORT},server,nowait"

# --- CLOUDLAB FIX: Handle Seed ISO ---
SEED_DRIVE=""
if [ ! -z "$SEED_ISO" ]; then
    SEED_DRIVE="-drive file=$SEED_ISO,format=raw,if=virtio"
fi

$QEMU_DIR/qemu-system-x86_64 \
-serial $REDIRECT \
-m ${MEM_SIZE}G \
-nographic \
-machine q35,accel=kvm,kernel-irqchip=split \
-cpu host,migratable=no,pmu=on,+tsc,+tsc-deadline,+rdtscp,+invtsc,+monitor \
$MEMORY \
$PCI_ROOT_PORT $NET $vIOMMU  \
-drive file=$IMAGE,if=virtio,format=qcow2 \
$SEED_DRIVE \
-smp ${NUM_CPUS},sockets=1 \
-numa node,nodeid=0,cpus=0${NUM_CPUS_MAX_STR},memdev=m0 \
-rtc clock=host \
$QMP \
-virtfs local,path=$SHARED_DIR_PATH,mount_tag=hostshare,security_model=none,id=hostshare \
-chardev socket,path="/tmp/qga.sock",server=on,wait=off,id=qga0 \
-device virtio-serial \
$PCI_HYPERUPCALL_BRIDGES \
-device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
-bios $SHARED_DIR_PATH/bios.bin \
$KERNEL \
"${APPEND[@]}"
