// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/fs.h> // BLKGETSIZE64, ...

#include <iostream>
#include <stdexcept>
#include <string>
#include <string.h>

#include <ixxx/util.hh>
#include <ixxx/posix.hh>


#include "pcap.hh"


static void copy(int dev, size_t off_a, size_t off_b, size_t bsize, int dest)
{
    unsigned char buf[bsize] __attribute__((aligned(4*1024)));

    size_t off_ali = off_a / bsize * bsize;
    size_t off_bli = off_b / bsize * bsize;

    if (off_ali < off_a) {
        ssize_t l = ixxx::posix::pread(dev, buf, bsize, off_ali);
        if (size_t(l) != bsize)
            throw std::runtime_error("incomplete dev read");
        size_t o = off_a - off_ali;

        ixxx::util::write_all(dest, buf + o, bsize - o);

        off_ali += bsize;
    }
    for (size_t i = off_ali; i < off_bli; i += bsize) {
        ssize_t l = ixxx::posix::pread(dev, buf, bsize, i);
        if (size_t(l) != bsize)
            throw std::runtime_error("incomplete dev read");
        ixxx::util::write_all(dest, buf, bsize);
    }
    if (off_bli < off_b) {
        ssize_t l = ixxx::posix::pread(dev, buf, bsize, off_bli);
        if (size_t(l) != bsize)
            throw std::runtime_error("incomplete dev read");
        size_t o = off_b - off_bli;
        ixxx::util::write_all(dest, buf, o);
    }
}

static uint64_t dev_size(int fd)
{
    uint64_t n = 0;
    int r = ioctl(fd, BLKGETSIZE64, &n);
    if (r == -1)
        throw std::runtime_error(std::string("ioctl(BLKGETSIZE64) failed: ") + strerror(errno));
    return n;
}

static int mainP(int argc, char **argv)
{
    if (argc < 5) {
        throw std::runtime_error(std::string("call: ") + argv[0] + " DEV BEGIN END DEST");
    }

    std::string dev_path { argv[1] };
    size_t off_a = atol(argv[2]);
    size_t off_b = atol(argv[3]);
    std::string dest_path { argv[4] };

    constexpr size_t bsize = 64lu * 1024;

    auto dev = ixxx::posix::open(dev_path, O_RDONLY | O_DIRECT | O_NOATIME);

    auto dest = ixxx::posix::open(dest_path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND);


    PCAP_Header h(default_pcap_header);
    ixxx::posix::write(dest, &h, sizeof h);

    if (off_a < off_b) {
        copy(dev, off_a, off_b, bsize, dest);
    } else {
        auto n = dev_size(dev);
        auto n_ali = n / bsize * bsize;
        copy(dev, off_a, n_ali, bsize, dest);
        copy(dev, 0, off_b, bsize, dest);
    }

    ixxx::posix::close(dest);

    return 0; // auto-close dev
}

int main(int argc, char **argv)
{
    try {
        return mainP(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << '\n';
    }
}
