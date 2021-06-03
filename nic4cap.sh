#!/bin/bash

set -eux

nic=$1
from=$2
to=$3
n=$((to - from + 1))

# e.g. up to 63
queues=$4

# we certainly don't want the capture interface reacting
# to router advertisements etc.
sysctl net.ipv6.conf.${nic}.accept_ra=0
sysctl net.ipv6.conf.${nic}.autoconf=0

# without `disable_ipv6` we still get a link-local address
# we don't need for capturing
sysctl net.ipv6.conf.${nic}.disable_ipv6=0

ip link set up $nic

# since we are still getting a IPv6 link local address (although ipv6 is disabled) ...
ip addr flush dev $nic

ip link set $nic promisc on

# enable HW-timestamping for received packets
hwstamp_ctl -i $nic -r1


# disable most offloading features
ethtool -k $nic \
    | grep -v '\[fixed\]$' \
    | grep '^[a-z].*on$' \
    | grep -v 'scatter-gather\|receive-hashing:' \
    | sed 's/: on/ off/' \
    | xargs -rn2 ethtool -K $nic

# capture all packets, even invalid ones!
# (certainly not available on all NICs ...)
ethtool -K $nic rx-all on

# increase the number of slots in receive queues/rings
ethtool -G $nic rx 4096

# reset to a safe value
ethtool -X $nic equal 1

# use just n receive queues
ethtool -L $nic combined $queues

# distribute hash-table slots over all receive queues
ethtool -X $nic equal $queues

# also hash udp src/dest port (in addition to src/dst address)
ethtool -N $nic rx-flow-hash udp4 sdfn


# otherwise it will mess with our assignments
systemctl stop irqbalance.service

i=$from
for irq in $(ls /sys/class/net/$nic/device/msi_irqs/* | cut -d/ -f8 | sort -n); do
    echo $i > /proc/irq/$irq/smp_affinity_list
    i=$((i + 1))
    if [ $i -gt $to ]; then
        i=$from
    fi
done

