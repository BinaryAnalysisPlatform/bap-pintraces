#include <boost/algorithm/string.hpp>

#include "bpt_events.hpp"
#include "bpt_bytes_io.hpp"
#include "bpt_visitor.hpp"

namespace bpt {

struct register_event::impl {
    impl(OPCODE op, REG r, const CONTEXT* ctx)
        : opcode(op)
        , reg(r)
        , bytes(io::from_reg(reg, ctx)) {}
    OPCODE opcode;
    REG reg;
    bytes_type bytes;
};

register_event::register_event(OPCODE opcode, REG reg, const CONTEXT* ctx)
    : pimpl(new impl(opcode, reg, ctx)) {}

const bytes_type& register_event::bytes() const {
    return pimpl->bytes;
}

std::size_t register_event::width() const {
    switch (REG_Width(pimpl->reg)) {
    case REGWIDTH_8: return 8;
    case REGWIDTH_16: return 16;
    case REGWIDTH_32: return 32;
    case REGWIDTH_64: return 64;
    case REGWIDTH_80: return 80;
    case REGWIDTH_128: return 128;
    case REGWIDTH_256: return 256;
    case REGWIDTH_512: return 512;
    case REGWIDTH_FPSTATE: return 16; /*FIXME: this is FSW register?*/
    case REGWIDTH_INVALID:
        std::cerr << "warning: invalid register width "
                  << name()
                  << std::endl;
        break;
    }
    return bytes().size() * 8;
}

std::string register_event::name() const {
    switch(pimpl->reg) {
    case REG_SEG_FS_BASE: return "FS_BASE";
    case REG_SEG_GS_BASE: return "GS_BASE";
    default:
        std::string name(REG_StringShort(pimpl->reg));
        boost::algorithm::to_upper(name);
        return name;
    }
}

OPCODE register_event::opcode() const {
    return pimpl->opcode;
}

read_event::read_event(OPCODE opcode, REG reg, const CONTEXT* ctx)
    : register_event(opcode, reg, ctx) {}

void read_event::do_accept(visitor& out) const {
    out.visit(*this);
}

write_event::write_event(OPCODE opcode, REG reg, const CONTEXT* ctx)
    : register_event(opcode, reg, ctx) {}

void write_event::do_accept(visitor& out) const {
    out.visit(*this);
}

std::ostream& pp(std::ostream& out, const register_event& e,
                 const std::string& d) {
    using namespace io::data;
    return out << e.name()
               << d
               << e.bytes()
               << ':'
               << e.width();
}

std::ostream& read_event::operator<<(std::ostream& out) const {
    return pp(out, *this, " => ");
}

std::ostream& write_event::operator<<(std::ostream& out) const {
    return pp(out, *this, " <= ");
}

} //namespace bpt
