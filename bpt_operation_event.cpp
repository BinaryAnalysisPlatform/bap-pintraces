#include "bpt_events.hpp"
#include "bpt_bytes_io.hpp"
#include "bpt_visitor.hpp"

namespace bpt {

struct operation_event::impl {
    impl(const char* d, OPCODE o, ADDRINT a, UINT32 size, THREADID t)
        : disasm(d)
        , opcode(o)
        , addr(a)
        , tid(t)
        , bytes(io::from_mem(addr, size)) {}
    const char* disasm;
    OPCODE opcode;
    ADDRINT addr;
    THREADID tid;
    bytes_type bytes;
};

operation_event::operation_event(const char* disasm, OPCODE opcode,
                     ADDRINT addr, UINT32 size, THREADID tid)
    : pimpl(new impl(disasm, opcode, addr, size, tid)) {}

OPCODE operation_event::opcode() const {
    return pimpl->opcode;
}

ADDRINT operation_event::addr() const {
    return pimpl->addr;
}

THREADID operation_event::tid() const {
    return pimpl->tid;
}

const bytes_type& operation_event::bytes() const {
    return pimpl->bytes;
}

std::string operation_event::name() const {
    return OPCODE_StringShort(pimpl->opcode);
}

const char* operation_event::disasm() const {
    return pimpl->disasm;
}

void operation_event::do_accept(visitor& out) const {
    out.visit(*this);
}

std::ostream& operation_event::operator<<(std::ostream& out) const {
    using namespace io::code;
    return out << this->name()
               << '('
               << this->tid()
               << ','
               << "0x"
               << std::hex
               << this->addr()
               << std::dec
               << ':'
               << sizeof(ADDRINT)*8
               << ')'
               << '['
               << this->bytes()
               << "] "
               << this->disasm();
}

} //namespace bpt
