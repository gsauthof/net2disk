// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later


#ifndef AIO_DEVICE_HH
#define AIO_DEVICE_HH



#include <vector>
#include <stdexcept>
#include <string.h>
#include <assert.h>

#include <linux/aio_abi.h>

#include <ixxx/linux.hh>

class Aio_Device {
    public:

        Aio_Device() =default;

        Aio_Device(const Aio_Device &) =delete;
        Aio_Device &operator=(const Aio_Device &) =delete;

        Aio_Device(
                const char *dev_name,
                size_t slice_size,
                size_t slice_count,
                unsigned io_depth = 32
                );

        ~Aio_Device();

        // precondition: n <= slice_size_
        void write(const unsigned char *v, size_t n)
        {
            // since pointer comparisons beyond 1 past the end
            // yield undefined behaviour ...
            if ((uintptr_t)(void*) p_ + n > (uintptr_t)(void*) end_) {
                size_t k = end_ - p_;
                fresh_size_ += k;
                p_ = static_cast<unsigned char *>(mempcpy(p_, v, k));
                submit();
                if (in_flight_[slice_idx_])
                    throw std::runtime_error("found stale uncompleted first slice");
                p_ = begin_;
                fresh_size_ += n-k;
                p_ = static_cast<unsigned char *>(mempcpy(p_, v+k, n-k));
            } else {
                fresh_size_ += n;
                if (fresh_size_ >= slice_size_) {
                    if (in_flight_[(slice_idx_ + 1) % slice_count_])
                        throw std::runtime_error("found stale uncompleted slice");
                }
                p_ = static_cast<unsigned char *>(mempcpy(p_, v, n));
                if (fresh_size_ >= slice_size_) {
                    submit();
                }
            }
        }

        size_t byte_offset() const
        {
            return off_ + fresh_size_;
        }

        // write out the last trailing buffered bytes, i.e. pad them
        // up to the slice size for the last write
        void close();

    private:
        enum { MAX_QUEUE_SIZE = 64 };

        int fd_ {-1};
        // first usable offset, i.e. after super-block and pointer-blocks
        aio_context_t ctx_ {0};

        uint64_t dev_size_ {0};
        size_t start_off_ {0};
        // current offset
        size_t off_ {start_off_};
        // one after last usable offset
        size_t dev_end_ {0};
        // write size
        size_t slice_size_ { 64 * 1024 };
        // the buffer is a sequence of slices
        size_t slice_count_ { 1024lu*1024lu*1024lu / slice_size_ };

        unsigned io_depth_ { 16 };
        unsigned submit_count_ {0};

        // buffer start
        unsigned char *begin_ { nullptr };
        // buffer end
        unsigned char *end_ {nullptr};

        // to keep track of which slice is completed
        size_t slice_idx_ {0};
        // current posititon in buffer, i.e. begin_ <= p_ < end_
        unsigned char *p_ {nullptr};

        // start of current slice, i.e. begin_ <= fresh_ <= p < end_
        unsigned char *fresh_ {nullptr};
        // current slice that isn't written
        // i.e. fresh_ + fresh_size_ = p_
        // prefix gets written if fresh_size_ >= slice_size_
        size_t fresh_size_ {0};


        // bool vector for slices that are submitted
        // XXX or even use std::vector<bool> here?
        std::vector<unsigned char> in_flight_; // i.e. size = slice_count_ + sector_count_

        struct iocb io_request_ {0};
        struct iocb *io_requests_[1] { &io_request_ };


        void submit()
        {
            if (submit_count_ == io_depth_) {
                reap_completions();
            }
            in_flight_[slice_idx_] = 1;

            // NB: io_submit() writes a zero into iocb::aoi_key ...
            io_request_.aio_data       = slice_idx_;
            io_request_.aio_lio_opcode = IOCB_CMD_PWRITE;
            io_request_.aio_fildes     = fd_;
            io_request_.aio_buf        = reinterpret_cast<uintptr_t>(fresh_);
            io_request_.aio_nbytes     = slice_size_;
            io_request_.aio_offset     = off_;

            int r = ixxx::linux::io_submit(ctx_, 1, io_requests_);
            if (r != 1)
                throw std::runtime_error("Could submit in submit()");

            ++submit_count_;

            off_ += slice_size_;
            assert(off_ <= dev_end_);
            if (off_ == dev_end_)
                off_ = start_off_;

            slice_idx_ = (slice_idx_ + 1) % slice_count_;
            assert(fresh_size_ >= slice_size_);
            fresh_size_ -= slice_size_;
            if (slice_idx_) {
                fresh_ += slice_size_;
            } else {
                assert(!fresh_size_);
                fresh_ = begin_;
                p_ = begin_;
            }
        }

        void reap_completions()
        {
            struct io_event evs[MAX_QUEUE_SIZE] = {0};
            assert(sizeof evs / sizeof evs[0] >= io_depth_);

            // XXX poll aio_ring?
            // cf. https://github.com/axboe/fio/blob/dfecde6a4b49bd299b2a7192c10533b9beb4820d/engines/libaio.c#L166-L205

            int r = ixxx::linux::io_getevents(ctx_, 1, io_depth_, evs, 0);
            //int r = ixxx::linux::io_getevents(ctx_, 1, 1, evs, 0);

            if (r == 0)
                throw std::runtime_error("nothing reaped");

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
        }
};

#endif // AIO_DEVICE_HH
