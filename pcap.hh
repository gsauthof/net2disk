#ifndef PCAP_HH
#define PCAP_HH

// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later


#include <stdint.h>

struct PCAP_Header {
    uint32_t magic;
    uint16_t major;
    uint16_t minor;
    int32_t timezone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};
extern const PCAP_Header default_pcap_header;

struct PCAP_Pkt_Header {
    uint32_t sec;
    uint32_t nsec; // or usec in old format
    uint32_t snaplen;
    uint32_t len;
};

#endif
