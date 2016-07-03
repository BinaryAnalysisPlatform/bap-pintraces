#include <boost/foreach.hpp>
#include "bpt_events.hpp"
#include "bpt_bytes_io.hpp"
#include "bpt_visitor.hpp"
#include "bpt_bytes_io.hpp"

namespace bpt {

struct syscall_event::impl {
#ifdef _WIN32
    static const int max_args = 9;
#else
    static const int max_args = 6;
#endif
    impl(THREADID t, const CONTEXT* ctx, SYSCALL_STANDARD std)
        : tid(t)
        , addr(PIN_GetContextReg(ctx, REG_INST_PTR))
        , number(PIN_GetSyscallNumber(ctx, std))
        , args(max_args) {
        for (int i=0, I = args.size(); i < I; ++i) {
            args[i] = PIN_GetSyscallArgument(ctx, std, i);
        }
    }
    THREADID tid;
    ADDRINT addr;
    ADDRINT number;
    std::vector<ADDRINT> args;
};

syscall_event::syscall_event(THREADID tid, const CONTEXT* ctx,
                             SYSCALL_STANDARD std)
    : pimpl(new impl(tid, ctx, std)) {}

ADDRINT syscall_event::addr() const {
    return pimpl->addr;
}

THREADID syscall_event::tid() const {
    return pimpl->tid;
}

ADDRINT syscall_event::number() const {
    return pimpl->addr;
}

const std::vector<ADDRINT>& syscall_event::args() const {
    return pimpl->args;
}

void syscall_event::do_accept(visitor& out) const {
    out.visit(*this);
}

std::ostream& syscall_event::operator<<(std::ostream& out) const {
    out << "SYSCALL: " << this->tid() << " ";
    io::pp_addr(out, this->addr());
    out << " ";
    io::pp_addr(out, this->number());
    out << " ( ";
    BOOST_FOREACH(ADDRINT addr, this->args()) {
        io::pp_addr(out, addr) << " ";
    }
    out << ")";
    return out;
}

} //namespace bpt
