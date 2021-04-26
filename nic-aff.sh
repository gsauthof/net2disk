#!/bin/bash

set -eux

nic=$1
from=$2
to=$3
n=$((to - from + 1))

# e.g. up to 63
queues=$4

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

