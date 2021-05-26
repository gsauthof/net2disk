// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "pcap.hh"

const PCAP_Header default_pcap_header = {
    .magic = 0xa1b23c4d, // i.e. ns resolution, use 0xa1b2c3d4 for us resolution
    .major = 2, // PCAP format version
    .minor = 4,
    .snaplen = 1522, // maximum captured packet size
    .network = 1 // ethernet
};
