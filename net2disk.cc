// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <algorithm>
#include <charconv> // to_chars
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <chrono>              // chrono_literals
#include <condition_variable>
#include <mutex>

#include <assert.h>
#include <stdlib.h>      // atoi, ...
#include <string.h>      // memset, ...
#include <sys/types.h>   // getpid, ...
#include <unistd.h>      // getopt, ...
#include <sys/mman.h>    // PROT_READ, ...

#include <sys/epoll.h>       // epoll_event
#include <sys/eventfd.h>     // EFD_SEMAPHORE
#include <sys/signalfd.h>    // signalfd_siginfo
#include <arpa/inet.h>       // htons, ...
#include <sys/socket.h>      // AF_PACKET, ...
#include <linux/if_ether.h>  // ETH_P_ALL, ...
#include <linux/if_packet.h>  // TPACKET_V3, ...
#include <linux/net_tstamp.h> // SOF_TIMESTAMPING_RAW_HARDWARE, ...
#include <x86intrin.h> // __mm_pause

#include <ixxx/ansi.hh>
#include <ixxx/linux.hh>
#include <ixxx/posix.hh>
#include <ixxx/socket.hh>
#include <ixxx/pthread.hh>
#include <ixxx/util.hh>
#include <ixxx/pthread_util.hh>
#include <ixxx/sys_error.hh>

#include "aio_device.hh"
#include "pcap.hh"


enum class Writer {
    MMAP,
    AIO
};

#ifndef NET2DISK_WRITER
#define NET2DISK_WRITER 1
#endif

static constexpr Writer writer =
#if NET2DISK_WRITER == 0
    Writer::MAP
#elif NET2DISK_WRITER == 1
    Writer::AIO
#else
#error "unknown NET2DISK_WRITER choice"
#endif
    ;

struct Args {

    Args();
    Args(int argc, char **argv);

    std::vector<unsigned> cores;
    unsigned sockets_per_core {1};

    std::string base_dir { "." };
    std::string interface;

    unsigned block_size { 32 * 1024 * 1024 };
    unsigned blocks { 64 };

    unsigned frame_size { 2048 };
    unsigned snaplen { 1522 };

    int fanout_group {0};

    unsigned file_count { 10 };
    size_t file_size { size_t(100) << 20 }; // 100 MiB

    unsigned stats_period_s { 60 };

    int efd { -1 };

    void help(std::ostream &o, const char *argv0);
};
Args::Args() =default;

void Args::help(std::ostream &o, const char *argv0)
{
    o << argv0 << " - copy packets from the net to disk\n"
        << "Usage: " << argv0 << " [OPT..] -i INTERFACE DESTINATION_DIR\n"
        << "\n"
        << "Options:\n"
        << "  -b BLOCK_SIZE  RX_RING block size for each reader thread in bytes (default: 32 MiB)\n"
        << "  -c CORE        reader thread core affinity - repeat for more than one reader thread\n"
        << "  -f FRAME_SIZE  maximum frame size to expect, must be a divisor of block size (default: 2048),\n"
        << "                 NB: the first 48 bytes or so are already used for a kernel struct\n"
        << "  -h             display this help\n"
        << "  -i INTERFACE   network interface to copy all the packets from\n"
        << "  -k #FILES      number of capture files to rotate (default: 10)\n"
        << "  -n #BLOCKS     number of RX_RING blocks in each reader thread (default: 64)\n"
        << "  -p SNAPLEN     maximum packets size to expect (default: 1522),\n"
        << "                 must fit into FRAME_SIZE\n"
        << "  -s FILE_SIZE   rotate pcap files after FILE_SIZE MiB (default: 100 MiB)\n"
        << "  -S #SOCKETS    number of AF_PACKET sockes per reader thread (default: 1)\n"
        << "\n"
        << "2021, Georg Sauthoff <mail@gms.tf>, GPLv3+\n";
}

Args::Args(int argc, char **argv)
{
    char c = 0;
    // '-' prefix: no reordering of arguments, non-option arguments are
    // returned as argument to the 1 option
    // ':': preceding option takes a mandatory argument
    while ((c = getopt(argc, argv, "-b:c:hi:k:n:p:S:s:")) != -1) {
        switch (c) {
            case '?':
                {
                    std::ostringstream o;
                    o << "unexpected option : -" << char(optopt) << '\n';
                    throw std::runtime_error(o.str());
                }
                break;
            case 'b':
                block_size = atoi(optarg);
                break;
            case 'c':
                cores.emplace_back(atoi(optarg));
                break;
            case 'h':
                help(std::cerr, argv[0]);
                exit(0);
                break;
            case 'i':
                interface = optarg;
                break;
            case 'k':
                file_count = atoi(optarg);
                break;
            case 'n':
                blocks = atoi(optarg);
                break;
            case 'p':
                snaplen = atoi(optarg);
                break;
            case 'S':
                sockets_per_core = atoi(optarg);
                break;
            case 's':
                file_size = size_t(atoi(optarg)) << 20;
                break;
            case 1:
                if (base_dir.empty())
                    base_dir = optarg;
                else
                    throw std::runtime_error("too many positional arguments");
                break;
        }
    }
    if (cores.empty())
        throw std::runtime_error("No cores specified for the reader thread (cf. -c)");
    if (interface.empty())
        throw std::runtime_error("No interface specified (cf. -i)");

    if (cores.size() > 1 || sockets_per_core > 1) {
        fanout_group = getpid() & 0xffff;
        fanout_group |= PACKET_FANOUT_CPU << 16;
    }
}

struct Spawn_Notifier {
    std::condition_variable cv;
    std::mutex mutex;
    bool initialized { false };
};

struct Reader_Args : public Args {
    Reader_Args();
    Reader_Args(const Args &o);

    std::string new_dir  { "/KAPPES/" };
    std::string tmp_dir  { "/KAPPES/" };
    std::string dev_path { "/KAPPES/dev" };


    unsigned index{0};
    unsigned core{0};

    pthread_t thread_id {0};
    Spawn_Notifier *notifier {nullptr};

    // XXX move to args
    unsigned spin_rounds {100};

    void set_core(unsigned core, unsigned index);
};
Reader_Args::Reader_Args() =default;
Reader_Args::Reader_Args(const Args &o)
    : Args(o)
{
}
void Reader_Args::set_core(unsigned core, unsigned index)
{
    this->core = core;
    this->index = index;

    new_dir = base_dir + '/' + std::to_string(index) + "/new";
    tmp_dir = base_dir + '/' + std::to_string(index) + "/tmp";

    dev_path = base_dir + '/' + std::to_string(index) + "/dev";
}


struct Rx_Ring {
    Rx_Ring();
    Rx_Ring(int fd, unsigned block_size, unsigned frame_size, unsigned blocks);

    ixxx::util::MMap mapping;
    std::vector<unsigned char*> block_addrs;

    unsigned block_size {0};
    unsigned frame_size {0};
};

Rx_Ring::Rx_Ring() =default;
Rx_Ring::Rx_Ring(int fd, unsigned block_size, unsigned frame_size, unsigned blocks)
    :
        block_size(block_size),
        frame_size(frame_size)
{
    struct tpacket_req3 req = {
        .tp_block_size = block_size,
        .tp_block_nr   = blocks,
        // with TPACKET_V3, when receiving packets, the kernel places variable
        // sized frames into the buffer (cf. tp_next_offset); we still
        // set tp_frame_size+tp_frame_nr here since the code in
        // https://elixir.bootlin.com/linux/latest/source/net/packet/af_packet.c
        // still checks it and it looks like the tp_frame_size is used as max frame size
        // in some places
        .tp_frame_size = frame_size,
        .tp_frame_nr   = blocks * block_size / frame_size,
        // partially filled block is 'retired' from the kernel after X ms:
        .tp_retire_blk_tov = 1000 // ms
    };

    ixxx::posix::setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof req);

    mapping = ixxx::util::MMap(0, block_size * blocks,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);

    unsigned char *p = mapping.begin();
    for (unsigned i = 0; i < blocks; ++i)
        block_addrs.emplace_back(p + i * block_size);

}

struct Reader {
    Reader_Args args;

    Reader() =default;
    Reader(const Reader_Args &args);
    void main();

    private:
    std::vector<Rx_Ring> rings;

    ixxx::util::FD tmp_dir_fd;
    ixxx::util::FD new_dir_fd;

    std::vector<ixxx::util::MMap> files;
    std::vector<std::string> filenames;
    unsigned file_idx {0};
    std::pair<unsigned char*, unsigned char *> slice { nullptr, nullptr };


    std::unique_ptr<Aio_Device> aio_dev;
    size_t last_sec {0};
    size_t last_off {0};


    size_t bytes_captured {0};
    size_t bytes_captured_old {0};
    size_t pkts_captured {0};
    size_t drops_captured {0};
    size_t freeze_captured {0};

    int mk_packet_socket();

    void rename_file();

    void map_files();
    void switch_file();

    void setup_aio_dev();
    void reference_chunk();

    void terminate();

    void print_stats(int fd, unsigned i);
    void print_delta_stats(int fd, unsigned i);

    void traverse_blocks();

    void write_packet(const unsigned char *begin, unsigned snaplen, unsigned len,
        unsigned sec, unsigned nsec);
};
Reader::Reader(const Reader_Args &args)
    : args(args)
{
    rings.reserve(args.sockets_per_core);
}

int Reader::mk_packet_socket()
{
    int fd = ixxx::posix::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    int version = TPACKET_V3;
    ixxx::posix::setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof version);

    rings.emplace_back(fd, args.block_size, args.frame_size, args.blocks);

    int ts_choice = SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE;
    ixxx::posix::setsockopt(fd, SOL_PACKET, PACKET_TIMESTAMP, &ts_choice, sizeof ts_choice);

    struct sockaddr_ll addr = {
        .sll_family   = PF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = int(ixxx::posix::if_nametoindex(args.interface.c_str()))
    };

    ixxx::posix::bind(fd, (struct sockaddr *) &addr, sizeof addr);

    if (args.fanout_group)
        ixxx::posix::setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
                &args.fanout_group, sizeof args.fanout_group);

    return fd;
}

static void read_tmp_files(int dfd, const std::string &tmp_dir, std::vector<std::string> &v)
{
    ixxx::util::Directory d(tmp_dir);
    while (const dirent *e = d.read()) {
        if (*e->d_name == '.')
            continue;

        struct stat st;
        ixxx::posix::fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW);

        if (!(st.st_mode & S_IFREG))
            continue;
        v.emplace_back(e->d_name);
    }
    std::sort(v.begin(), v.end());
}

void Reader::rename_file()
{
    struct timespec tp;
    ixxx::posix::clock_gettime(CLOCK_REALTIME, &tp);
    struct tm g;
    ixxx::posix::gmtime_r(&tp.tv_sec, &g);
    char fn[4+2*2+2 + 1 +  3*2+2 + 1 + 1 + 5];
    ixxx::ansi::strftime(fn, sizeof fn, "%FT%TZ.pcap", &g);

    ixxx::posix::renameat(tmp_dir_fd, filenames[file_idx],
            tmp_dir_fd, fn);
    filenames[file_idx] = fn;
}

void Reader::map_files()
{
    tmp_dir_fd = ixxx::util::FD{ ixxx::posix::open(args.tmp_dir, O_RDONLY | O_PATH | O_DIRECTORY) };
    read_tmp_files(tmp_dir_fd, args.tmp_dir, filenames);

    if (filenames.empty())
        throw std::runtime_error("temporary director " + args.tmp_dir + " is empty!");

    for (auto &fn : filenames) {
        ixxx::util::FD fd { tmp_dir_fd, fn, O_RDWR };
        files.emplace_back(ixxx::util::mmap_file(fd, true, true, args.file_size));
    }

    slice.first  = files[0].begin();
    slice.second = files[0].end();

    rename_file();
}

void Reader::setup_aio_dev()
{
    size_t slice_size = 64lu * 1024;
    aio_dev.reset(new Aio_Device(args.dev_path.c_str(),
                slice_size, 1024lu * 1024 * 1024 / slice_size));
}


void Reader::switch_file()
{
    ixxx::posix::linkat(tmp_dir_fd, filenames[file_idx],
            new_dir_fd, filenames[file_idx], 0);
    file_idx = (file_idx + 1) % files.size();

    slice.first  = files[file_idx].begin();
    slice.second = files[file_idx].end();

    PCAP_Header h(default_pcap_header);
    h.snaplen = args.snaplen;
    slice.first = static_cast<unsigned char *>(mempcpy(slice.first, &h, sizeof h));

    rename_file();
}

void Reader::reference_chunk()
{
    struct tm g;
    time_t t = last_sec;
    ixxx::posix::gmtime_r(&t, &g);
    char fn[4+2*2+2 + 1 +  3*2+2 + 2  + 2*20 + 1 + 1] = {0};
    ixxx::ansi::strftime(fn, sizeof fn, "%FT%TZ_", &g);
    char *p = fn + 4+2*2+2 + 1 +  3*2+2 + 2;
    auto r = std::to_chars(p, fn+sizeof fn-1, last_off);
    if (r.ec != std::errc())
        throw std::runtime_error("couldn't convert last offset");

    p = r.ptr;
    *p = '-';
    ++p;
    last_off = aio_dev->byte_offset();
    r = std::to_chars(p, fn+sizeof fn-1, last_off);
    if (r.ec != std::errc())
        throw std::runtime_error("couldn't convert byte offset");
    p = r.ptr;
    *p = 0;

    int x = ixxx::posix::openat(new_dir_fd, fn, O_CREAT | O_DIRECT | O_WRONLY, 0644);
    ixxx::posix::close(x);
}

void Reader::write_packet(const unsigned char *begin, unsigned snaplen, unsigned len,
        unsigned sec, unsigned nsec)
{
    PCAP_Pkt_Header h = {
        .sec = sec,
        .nsec = nsec,
        .snaplen = snaplen,
        .len = len
    };

    if (writer == Writer::MMAP) {
        unsigned char *e = slice.first + sizeof h + snaplen;

        if (e > slice.second) {
            memset(slice.first, 0, slice.second - slice.first);
            switch_file();
        }
        assert(size_t(slice.second - slice.first) >= sizeof h + snaplen);

        slice.first = static_cast<unsigned char*>(mempcpy(slice.first, &h, sizeof h));
        slice.first = static_cast<unsigned char*>(mempcpy(slice.first, begin, snaplen));

    } else if (writer == Writer::AIO) {
        if (sec >= last_sec + 60) {
            if (last_sec)
                reference_chunk();
            last_sec = sec / 60 * 60;
        }

        aio_dev->write(reinterpret_cast<unsigned char*>(&h), sizeof h);
        aio_dev->write(begin, snaplen);
    }

    bytes_captured += snaplen;
}

void Reader::traverse_blocks()
{
    for (auto &ring : rings) {
    for (unsigned char *p : ring.block_addrs) {
        // using this as a barrier operation to create objects - like the proposed std::bless()
        // We do this such that we implicitly re-create tpacket3_hdr objects on each traverse_blocks()
        // invocation since the kernel re-uses each block and on each reuse the new tpacket3_hdr
        // might overlay partly.
        // Thus, an overly analytic compiler might deduce such created objects are impossible
        // which would make the program's behavior undefined.
        // cf. http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p0593r5.html#when-to-create-objects
        new (p) std::byte[ring.block_size];
        // NB: for the implicit creation of tpacket_block_desc objects alone we don't need the
        // above barrier because mmap() likely is implementation-defined as creating objects.

        // exploiting C++'s implicit object creation rules
        // (which are similar to C's effective type rules)
        // cf. https://en.cppreference.com/w/cpp/language/object
        // cf. https://en.cppreference.com/w/c/language/object#Effective_type
        tpacket_block_desc *desc = reinterpret_cast<tpacket_block_desc*>(p);
        if (__atomic_load_n(&desc->hdr.bh1.block_status, __ATOMIC_ACQUIRE) & TP_STATUS_USER) {
            // not using atomic loads for the next two fields because the kernel should sequence
            // the block_status write before the other field writes
            uint32_t n   = desc->hdr.bh1.num_pkts;
            uint32_t off = desc->hdr.bh1.offset_to_first_pkt;

            unsigned char *b = p + off;

            for (unsigned i = 0; i < n;  ++i) {
                // C++ implicit object creation ok here because of the above barrier
                tpacket3_hdr *pkt = reinterpret_cast<tpacket3_hdr*>(b);
                // otherwise, we would need to do something like this:
                // tpacket3_hdr pkt;
                // memcpy(&pkt, b, sizeof pkt);

                // NB: tp_snaplen is the distance from tp_mac to packed end
                // NB: [tp_mac .. tp_net] is the ethernet header which is
                // ususally 14 bytes long - cf. ETH_HLEN
                // however, this isn't necessarily the complete header as seen on the cable,
                // i.e. the VLAN ID is missing and is returned out of band via
                // tpacket3_hdr::hv1::tp_vlan_tci/tp_vlan_tpid
                // iff tpacket_hdr::tp_status & TP_STATUS_VLAN_VALID/TP_STATUS_VLAN_VALID
                write_packet(b + pkt->tp_mac, pkt->tp_snaplen, pkt->tp_len,
                        pkt->tp_sec, pkt->tp_nsec);

                b += pkt->tp_next_offset;
            }

            // 'un-retire' bock, i.e. give it back to the kernel
            __atomic_store_n(&desc->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
        }
    }
    }
}

void Reader::terminate()
{
    if (writer == Writer::MMAP) {
        ixxx::posix::truncate(args.tmp_dir + '/' + filenames[file_idx],
                slice.first - files[file_idx].begin());

        ixxx::posix::linkat(tmp_dir_fd, filenames[file_idx],
                new_dir_fd, filenames[file_idx], 0);
    } else {
        reference_chunk();
        aio_dev->close();
    }
}

void Reader::print_stats(int fd, unsigned i)
{
    struct tpacket_stats_v3 stats;
    socklen_t n = sizeof stats;
    ixxx::posix::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &n);
    if (n != sizeof stats)
        throw std::runtime_error("Unexpected tpacket_stats_v3 size");

    pkts_captured += stats.tp_packets;
    drops_captured += stats.tp_drops;
    freeze_captured += stats.tp_freeze_q_cnt;

    std::cout << "Reader " << args.index << " (Core "  << args.core << ",Socket " << i << ") captured: "
        << bytes_captured << " bytes, "
        << pkts_captured  << " pkts, " << drops_captured << " dropped, "
        << freeze_captured << " freeze_q_cnt\n";
}
void Reader::print_delta_stats(int fd, unsigned i)
{
    struct tpacket_stats_v3 stats;
    socklen_t n = sizeof stats;
    // NB: getting the counters resets them
    ixxx::posix::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &n);
    if (n != sizeof stats)
        throw std::runtime_error("Unexpected tpacket_stats_v3 size");

    unsigned s = args.stats_period_s;

    size_t bytes = bytes_captured - bytes_captured_old;
    bytes_captured_old = bytes_captured;
    bytes /= s;

    unsigned pkts = stats.tp_packets;
    pkts_captured += pkts;
    pkts /= s;
    unsigned drops = stats.tp_drops;
    drops_captured += drops;
    unsigned drops_s = drops / s;
    unsigned freeze = stats.tp_freeze_q_cnt;
    freeze_captured += freeze;
    unsigned freeze_s = freeze / s;

    std::cout << "Reader " << args.index << " (Core "  << args.core << ", Socket " << i << ") captured: "
        << bytes << " bytes/s, "
        << pkts << " pkts/s, " << drops_s << " drops/s (" << drops << " per period), "
        << freeze_s << " freeze_q_cnt/s (" << freeze << " per period)\n";
}


void Reader::main()
{
    switch (writer) {
        case Writer::MMAP:
          map_files();
          break;
        case Writer::AIO:
          setup_aio_dev();
          break;
    }
    new_dir_fd = ixxx::util::FD{ ixxx::posix::open(args.new_dir, O_RDONLY | O_PATH | O_DIRECTORY) };

    ixxx::util::FD efd { ixxx::linux::epoll_create1(0) };
    {
        struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = args.efd } };
        ixxx::linux::epoll_ctl(efd, EPOLL_CTL_ADD, args.efd, &ev);
    }

    std::vector<ixxx::util::FD> fds;
    fds.reserve(args.sockets_per_core);
    for (unsigned i = 0; i < args.sockets_per_core; ++i) {
        fds.emplace_back(mk_packet_socket());
        int fd = fds.back();
        struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = fd } };
        ixxx::linux::epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
    }

    // make sure that packet sockets are created in a deterministic order
    {
        std::lock_guard<std::mutex> lock(args.notifier->mutex);
        args.notifier->initialized = true;
    }
    args.notifier->cv.notify_one();

    ixxx::util::FD tfd { ixxx::linux::timerfd_create(CLOCK_REALTIME, 0) };
    {
        struct itimerspec spec = {
            .it_interval = {
                .tv_sec = args.stats_period_s
            },
            .it_value = {
                .tv_sec = args.stats_period_s,
                .tv_nsec = 89321 // let it drift a little bit
            }
        };
        ixxx::linux::timerfd_settime(tfd, 0, &spec,  0);
        struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = tfd } };
        ixxx::linux::epoll_ctl(efd, EPOLL_CTL_ADD, tfd, &ev);
    }

    if (writer == Writer::MMAP) {
        PCAP_Header h(default_pcap_header);
        h.snaplen = args.snaplen;
        slice.first = static_cast<unsigned char *>(mempcpy(slice.first, &h, sizeof h));
    }


    struct epoll_event evs[3];
    for (;;) {
        for (unsigned i = 0; i < args.spin_rounds; ++i) {
            traverse_blocks();
            _mm_pause();
        }
        int k = ixxx::linux::epoll_wait(efd, evs, sizeof evs / sizeof evs[0], -1);
        for (int i = 0; i < k; ++i) {
            int xd = evs[i].data.fd;

            if (xd == args.efd) {
                // we don't even have to read that eventfd because
                // we terminate in any case ...
                unsigned i = 0;
                for (int fd : fds) {
                    print_stats(fd, i++);
                }
                terminate();
                return;
            } else if (xd == tfd) {
                uint64_t n = 0;
                auto l = ixxx::posix::read(tfd, &n, sizeof n);
                if (l != sizeof n)
                    throw std::runtime_error("partial read from timerfd");

                unsigned i = 0;
                for (int fd : fds) {
                    print_delta_stats(fd, i++);
                }
            }
        }
    }
}


static void setup_files(const std::string &base_dir, size_t file_size, size_t file_count)
{
    for (auto x : { "/tmp", "/new" }) {
        try {
            ixxx::posix::mkdir(base_dir + x, 0775);
        } catch (const ixxx::mkdir_error &e) {
            if (e.code() != EEXIST)
                throw;
        }
    }

    std::string tmp_dir { base_dir + "/tmp" };

    ixxx::util::FD dfd{ ixxx::posix::open(tmp_dir, O_RDONLY | O_PATH | O_DIRECTORY) };
    std::vector<std::string> v;
    read_tmp_files(dfd, tmp_dir, v);

    if (v.size() > file_count) {
        size_t n = v.size() - file_count;
        for (size_t i = 0; i < n; ++i)
            ixxx::posix::unlinkat(dfd, v[i], 0);
        v.erase(v.begin(), v.begin() + n);
    }

    for (auto &e : v) {
        ixxx::posix::truncate(tmp_dir + "/" + e, file_size);
    }

    size_t b = 1;
    size_t i = v.size();
    for (size_t k = i; k < file_count; ++k) {
        for (;; ++b) {
            struct tm g;
            time_t a = b;
            ixxx::posix::gmtime_r(&a, &g);
            char fn[4+2*2+2 + 1 +  3*2+2 + 1 + 1 + 5];
            ixxx::ansi::strftime(fn, sizeof fn, "%FT%TZ.pcap", &g);

            try {
                ixxx::util::FD fd { dfd, fn, O_WRONLY | O_CREAT | O_EXCL };
                ixxx::posix::ftruncate(fd, file_size);
            } catch (const ixxx::openat_error &e) {
                if (e.code() == EEXIST)
                    continue;
                else
                    throw;
            }

            break;
        }
    }

}
static void setup_files(const std::string &base_dir, size_t file_size, size_t file_count,
        size_t no_readers)
{
    std::string t { base_dir };
    for (size_t i = 0; i < no_readers; ++i) {
        t += '/';
        t += std::to_string(i);

        try {
            ixxx::posix::mkdir(t, 0775);
        } catch (const ixxx::mkdir_error &e) {
            if (e.code() != EEXIST)
                throw;
        }

        setup_files(t, file_size, file_count);
        t.resize(base_dir.size());
    }
}

static void setup_aio(const std::string &base_dir, size_t no_readers)
{
    std::string t { base_dir };
    t += '/';
    auto n = t.size();
    for (size_t i = 0; i < no_readers; ++i) {
        t += std::to_string(i);

        try {
            ixxx::posix::mkdir(t, 0775);
        } catch (const ixxx::mkdir_error &e) {
            if (e.code() != EEXIST)
                throw;
        }

        t += '/';
        auto m = t.size();
        for (auto x : { "/tmp", "/new" }) {
            t += x;
            try {
                ixxx::posix::mkdir(t, 0775);
            } catch (const ixxx::mkdir_error &e) {
                if (e.code() != EEXIST)
                    throw;
            }
            t.resize(m);
        }

        t += "/dev";
        try {
            struct stat st;
            ixxx::posix::stat(t, &st);
        } catch (const ixxx::stat_error &e) {
            if (e.code() == ENOENT)
                throw std::runtime_error("dev link is missing in reader director");
            throw;
        }

        t.resize(n);
    }
}

static void *reader_main(void *v)
{
    const Reader_Args *ra = static_cast<Reader_Args*>(v);
    try {
        Reader reader {*ra};
        reader.main();
    } catch (const std::exception &e) {
        std::cerr << "Reader " << ra->index << " on core "
            << ra->core << " failed: " << e.what() << '\n';

        uint64_t i = ra->cores.size() + 1;
        ssize_t n = ixxx::posix::write(ra->efd, &i, sizeof i);
        if (n != sizeof i)
            std::cerr << "Reader " << ra->index << " on core "
                << ra->core << " failed: partial eventfd write\n";

        return (void*)-1;
    }
    return 0;
}

static void spawn_readers(const Args &args, std::vector<Reader_Args> &ras)
{
    unsigned i = 0;
    ras.resize(args.cores.size());
    Spawn_Notifier sn;
    for (auto core : args.cores) {
        ras[i] = args;
        auto &a = ras[i];

        a.set_core(core, i);
        a.notifier = &sn;

        ixxx::util::Pthread_Attr attr;
        {
            cpu_set_t cpus;
            CPU_ZERO(&cpus);
            CPU_SET(core, &cpus);
            ixxx::posix::pthread_attr_setaffinity_np(attr.ibute(), sizeof cpus, &cpus);
        }

        ixxx::posix::pthread_create(&a.thread_id, attr.ibute(), reader_main,
                const_cast<void*>(static_cast<const void*>(&a)));

        // wait until the reader has joined the fanout-group such that the
        // group ordering is deterministic
        {
            std::unique_lock<std::mutex> lock(sn.mutex);
            using namespace std::chrono_literals;
            bool success = sn.cv.wait_for(lock, 3s, [&sn]{ return sn.initialized; });
            if (!success)
                throw std::runtime_error("reader thread start timed out");
            sn.initialized = false;
        }

        ++i;
    }
}


static int mainP(int argc, char **argv)
{
    Args args(argc, argv);
    switch (writer) {
        case Writer::MMAP:
            setup_files(args.base_dir, args.file_size, args.file_count, args.cores.size());
            break;
        case Writer::AIO:
            setup_aio(args.base_dir, args.cores.size());
            break;
    }

    ixxx::util::FD efd { ixxx::linux::eventfd(0, EFD_SEMAPHORE) };
    args.efd = efd.get();

    sigset_t sig_mask;
    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, SIGINT);
    sigaddset(&sig_mask, SIGTERM);
    sigaddset(&sig_mask, SIGQUIT);

    ixxx::posix::sigprocmask(SIG_BLOCK, &sig_mask, nullptr);
    ixxx::util::FD sfd { ixxx::linux::signalfd(-1, &sig_mask, 0) };

    ixxx::util::FD pfd { ixxx::linux::epoll_create1(0) };
    for (auto fd : { int(efd), int(sfd) }) {
        struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = fd } };
        ixxx::linux::epoll_ctl(pfd, EPOLL_CTL_ADD, fd, &ev);
    }

    std::vector<Reader_Args> ras;
    spawn_readers(args, ras);

    struct epoll_event evs[2];
    int k = ixxx::linux::epoll_wait(pfd, evs, sizeof evs / sizeof evs[0], -1);
    for (int i = 0; i < k; ++i) {
        int fd = evs[i].data.fd;
        if (fd == sfd) {
            struct signalfd_siginfo sigi;
            ssize_t n = ixxx::posix::read(sfd, &sigi, sizeof sigi);
            if (n != sizeof sigi)
                throw std::runtime_error("partial signalfd read");

            std::cout << "Terminating after receiving signal " << sigi.ssi_signo << " ...\n";
        } else {
            std::cout << "Terminating after a reader failed ...\n";
        }
    }

    uint64_t i = args.cores.size();
    ssize_t n = ixxx::posix::write(efd, &i, sizeof i);
    if (n != sizeof i)
        throw std::runtime_error("partial eventfd write");

    bool success = true;
    for (auto & ra: ras) {
        void *v = nullptr;
        ixxx::posix::pthread_join(ra.thread_id, &v);
        success = success && !v;
    }

    return !success;
}

int main(int argc, char **argv)
{
    try {
        return mainP(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "net2disk failed: " << e.what() << '\n';
    }
    return 1;
}
