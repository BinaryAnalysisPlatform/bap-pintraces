#include <boost/range.hpp>
#include <boost/foreach.hpp>

#include "bpt_events.hpp"
#include "bpt_visitor.hpp"

namespace bpt {

namespace RFLAGS {
struct field {
    field(const std::string& n, std::size_t p, std::size_t w = 1)
        : name(n), pos(p), width(w) {}
    std::string name;
    std::size_t pos;
    std::size_t width;
};

const field_ptr ID(new field("ID", 21));
const field_ptr VIP(new field("VIP", 20));
const field_ptr VIF(new field("VIF", 19));
const field_ptr AC(new field("AC", 18));
const field_ptr VM(new field("VM", 17));
const field_ptr RF(new field("RF", 16));
const field_ptr NT(new field("NT", 14));
const field_ptr IOPL(new field("IOPL", 12, 2));
const field_ptr OF(new field("OF", 11));
const field_ptr DF(new field("DF", 10));
const field_ptr IF(new field("IF", 9));
const field_ptr TF(new field("TF", 8));
const field_ptr SF(new field("SF", 7));
const field_ptr ZF(new field("ZF", 6));
const field_ptr AF(new field("AF", 4));
const field_ptr PF(new field("PF", 2));
const field_ptr CF(new field("CF", 0));

}

flag::flag(const RFLAGS::field_ptr& f, effect_type e)
    : field(f), mask(e) {}

const std::string& flag::name() const {
    return field->name;
}

int flag::effect() const {
    return mask;
}

std::size_t flag::width() const {
    return field->width;
}

bytes_type::value_type flag::value(const bytes_type& bytes) const {
    std::size_t pos = field->pos;
    std::size_t width = field->width;
    std::size_t byte = pos/8;
    std::size_t bit = pos%8;
    assert(width == 1 || width == 2);
    std::size_t mask = width == 1 ? 0x1 : 0x3;
    return (bytes[byte] >> bit) & mask;
}

flags_type init_flags() {
    static flag f[] = {
        flag(RFLAGS::ID, NONE),
        flag(RFLAGS::VIP, NONE),
        flag(RFLAGS::VIF, NONE),
        flag(RFLAGS::AC, NONE),
        flag(RFLAGS::VM, NONE),
        flag(RFLAGS::RF, NONE),
        flag(RFLAGS::NT, NONE),
        flag(RFLAGS::IOPL, NONE),
        flag(RFLAGS::OF, RD | WR),
        flag(RFLAGS::DF, RD | WR),
        flag(RFLAGS::IF, NONE),
        flag(RFLAGS::TF, NONE),
        flag(RFLAGS::SF, RD | WR),
        flag(RFLAGS::ZF, RD | WR),
        flag(RFLAGS::AF, RD | WR),
        flag(RFLAGS::PF, RD | WR),
        flag(RFLAGS::CF, RD | WR)
    };
    return flags_type(boost::begin(f), boost::end(f));
}

const flags_type all(init_flags());

read_flags_event::read_flags_event(OPCODE opcode, REG reg, const CONTEXT* ctx)
    : read_event(opcode, reg, ctx) {}


const flags_type& read_flags_event::flags() const {
    return all;
}

void read_flags_event::do_accept(visitor& out) const {
    out.visit(*this);
}

write_flags_event::write_flags_event(OPCODE opcode, REG reg, const CONTEXT* ctx)
    : write_event(opcode, reg, ctx) {}

const flags_type& write_flags_event::flags() const {
    return all;
}

void write_flags_event::do_accept(visitor& out) const {
    out.visit(*this);
}

template <typename B, typename E>
std::ostream& pp(std::ostream& out, const E& e, const std::string& d) {
    e.B::operator<<(out) << " [";
    std::string s = "";
    BOOST_FOREACH(const flag& f, e.flags()) {
        if (f.effect() & RD) {
            out << s
                << f.name()
                << d
                << static_cast<unsigned>(f.value(e.bytes()));
            s = ", ";
        }
    }
    out << "]";
    return out;

}
std::ostream& read_flags_event::operator<<(std::ostream& out) const {
    return pp<read_event>(out, *this, " => ");
}

std::ostream& write_flags_event::operator<<(std::ostream& out) const {
    return pp<write_event>(out, *this, " <= ");
}


} //namespace bpt

