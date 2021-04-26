This repository contains net2disk - a tool that implements memory-mapped
packet capturing under Linux.

Net2disk memory-maps packet buffers for incoming packets and the
target pcap files. Thus, it's quite efficient since system-calls
for receiving packets, getting their timestamps and finally
writing them to disk are eliminated. Also, this reduces the
number of memory copy operations.

2021, Georg Sauthoff <mail@gms.tf>


## Setup Considerations

Net2disk assumes that the captured interface is properly
configured, i.e. that it's already in promiscuous mode, receive
hardware timestamps are enabled, etc.

Also, one has to review some NIC parameters and likely tune them,
such as the number of receive queues, queue sizes, interrupt
affinities etc. This repository contains an example script
(`nic4cap.sh`) that can be used at starting point, but this is a
highly vendor specific task.

Regarding CPU (core) affinities: with net2disk you specify the
number of capture threads and to which CPU cores they are pinned.
One strategy is then to pin the receive queue interrupts to a
disjoint CPU core set. Under such a configuration, a NIC driver
can switch from interrupts to polling (i.e. at high packet rates,
cf. NAPI) without impacting the capture threads.



## Dependencies

- C++17
- cmake
- [libixxx](https://github.com/gsauthof/libixxx)
- [libixxxutil](https://github.com/gsauthof/libixxxutil)

