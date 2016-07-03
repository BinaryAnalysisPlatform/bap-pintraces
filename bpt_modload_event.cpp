#include "bpt_events.hpp"
#include "bpt_bytes_io.hpp"
#include "bpt_visitor.hpp"
#include "bpt_bytes_io.hpp"

namespace bpt {

struct modload_event::impl {
    impl(IMG img)
        : name(IMG_Name(img))
        , high(IMG_HighAddress(img))
        , low(IMG_LowAddress(img)) {}
    const std::string name;
    ADDRINT high;
    ADDRINT low;
};

modload_event::modload_event(IMG img)
    : pimpl(new impl(img)) {}

const std::string& modload_event::name() const {
    return pimpl->name;
}

ADDRINT modload_event::high() const {
    return pimpl->high;
}

ADDRINT modload_event::low() const {
    return pimpl->low;
}

void modload_event::do_accept(visitor& out) const {
    out.visit(*this);
}

std::ostream& modload_event::operator<<(std::ostream& out) const {
    out << "MLE: ";
    io::pp_addr(out, this->high());
    out << " - ";
    io::pp_addr(out, this->low());
    return out << " " << this->name();
}

} //namespace bpt
