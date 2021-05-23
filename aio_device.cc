#include "aio_device.hh"

#include <linux/mman.h> // MAP_HUGE_1GB, ...
#include <linux/fs.h> // BLKGETSIZE64, ...
#include <sys/ioctl.h>

#include <unistd.h> // close()
#include <ixxx/posix.hh>

Aio_Device::Aio_Device(
        const char *dev_name,
        size_t slice_size,
        size_t slice_count,
        unsigned io_depth
        )
    :
        slice_size_(slice_size),
        slice_count_(slice_count),
        io_depth_(io_depth),
        in_flight_(slice_count)
{
    if (io_depth > MAX_QUEUE_SIZE)
        throw std::runtime_error("max queue size exceeded");

    ixxx::linux::io_setup(io_depth, &ctx_);

    fd_ = ixxx::posix::open(dev_name, O_RDWR | O_DIRECT | O_NOATIME);

    int r = ioctl(fd_, BLKGETSIZE64, &dev_size_);
    if (r == -1)
        throw std::runtime_error("couldn't get size of " + std::string(dev_name) + ": "
                + strerror(errno));
    dev_end_ = dev_size_ / slice_size * slice_size;
    r = ioctl(fd_, BLKFLSBUF); // flush kernel's buffer cache
    if (r == -1)
        throw std::runtime_error("couldn't flush buffer cache of " + std::string(dev_name) + ": "
                + strerror(errno));


    size_t n = slice_size_ * slice_count_;
    begin_ = static_cast<unsigned char*>(ixxx::posix::mmap(0, n, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_1GB, -1, 0));
    p_ = begin_;
    fresh_ = p_;
    end_ = begin_ + n;
}

Aio_Device::~Aio_Device()
{
    if (begin_)
        ixxx::posix::munmap(begin_, end_ - begin_);

    if (fd_ != -1)
        ::close(fd_);

    if (ctx_) {
        try {
            ixxx::linux::io_destroy(ctx_);
        } catch (const std::exception &) {
            // we can't do nothing at this point
        }
    }
}


// write out the last trailing buffered bytes, i.e. pad them
// up to the slice size for the last write
void Aio_Device::close()
{
    if (fresh_size_) {
        assert(slice_size_ > fresh_size_);
        size_t k = slice_size_ - fresh_size_;
        memset(p_, 0, k);
        p_ += k;
        if (p_ == end_)
            p_ = begin_;
        fresh_size_ += k;
        submit();
    }

    struct io_event evs[64] = {0};
    assert(sizeof evs / sizeof evs[0] >= io_depth_);

    int r = ixxx::linux::io_getevents(ctx_, submit_count_, submit_count_, evs, 0);

    for (int i = 0; i < r; ++i ) {
        assert(submit_count_);
        --submit_count_;
        unsigned x = evs[i].data;
        in_flight_.at(x) = 0;
        if (evs[i].res < 0)
            throw std::runtime_error("got async write error");
        if (size_t(evs[i].res) != slice_size_)
            throw std::runtime_error("partial async write");
    }

    ixxx::posix::close(fd_);
    fd_ = -1;

    ixxx::linux::io_destroy(ctx_);
    ctx_ = 0;
}
