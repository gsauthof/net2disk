// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later


#include <ixxx/util.hh>
#include <ixxx/posix.hh>

#include "aio_device.hh"

#include <iostream>
#include <string>
#include <random>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
    if (argc < 5) {
        std::cerr << "call: " << argv[0] << " DEVICE IO_DEPTH BLOCK_SIZE_KB N\n";
        return 1;
    }

    const char     *dev_name = argv[1];
    unsigned        io_depth = atoi(argv[2]);
    size_t     block_size_kb = atoi(argv[2]);
    unsigned               n = atoi(argv[4]);

    size_t k = block_size_kb;
    Aio_Device dev(dev_name,
            k * 1024,
            1024lu * 1024 * 1024 / (k * 1024),
            io_depth);


    unsigned char buf[k * 1024] = {0};

    {
        ixxx::util::FD fd { "/dev/urandom", O_RDONLY };
        size_t l = ixxx::posix::read(fd, buf, sizeof buf);
        assert(l == sizeof buf);
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(72, 1530);
    //std::uniform_int_distribution<> dist(60lu * 1024, 64lu * 1024 - 1);

    for (unsigned i = 0; i < n; ++i) {
        size_t l = dist(gen);
        dev.write(buf, l);
    }

    dev.close();
    

    return 0;
}

