#include "bpt_events.hpp"
#include "bpt_bytes_io.hpp"
#include "bpt_visitor.hpp"

namespace bpt {

struct memory_event::impl {
    impl(ADDRINT a, UINT32 size)
        : addr(a)
        , bytes(size) {
        PIN_SafeCopy(static_cast<VOID*>(&bytes[0]),
                     reinterpret_cast<VOID*>(addr), size);
    }
    ADDRINT addr;
    bytes_type bytes;
};

memory_event::memory_event(ADDRINT addr, UINT32 size)
    : pimpl(new impl(addr, size)) {}

ADDRINT memory_event::addr() const {
    return pimpl->addr;
}

const bytes_type& memory_event::bytes() const {
    return pimpl->bytes;
}

load_event::load_event(ADDRINT addr, UINT32 size) : memory_event(addr, size) {}

void load_event::do_accept(visitor& out) const {
    out.visit(*this);
}

store_event::store_event(ADDRINT addr, UINT32 size) : memory_event(addr, size) {}

void store_event::do_accept(visitor& out) const {
    out.visit(*this);
}

std::ostream& pp(std::ostream& out, const memory_event& e,
                 const std::string& d) {
    using namespace io::data;
    return out << "0x"
               << std::hex
               << std::uppercase
               << e.addr()
               << std::dec
               << ':'
               << sizeof(ADDRINT)*8
               << d
               << e.bytes()
               << ':'
               << e.bytes().size()*8;
}

std::ostream& load_event::operator<<(std::ostream& out) const {
    return pp(out, *this, " => ");
}

std::ostream& store_event::operator<<(std::ostream& out) const {
    return pp(out, *this, " <= ");
}

} //namespace bpt
