#include <iostream>
#include <fstream>
#include <map>
#include <boost/range.hpp>
#include <boost/foreach.hpp>
#include "bpt_events.hpp"
#include "bpt_inst_counter.hpp"

namespace bpt {

typedef std::map<OPCODE, std::size_t> map_type;
struct inst_counter::impl {
    impl(const std::string& f) : file(f) {}
    std::string file;
    map_type map;
};

inst_counter::inst_counter(const std::string& file)
    : pimpl(new impl(file)) {}

void inst_counter::visit(const event&) {};
void inst_counter::visit(const modload_event&) {};
void inst_counter::visit(const syscall_event&) {};
void inst_counter::visit(const read_event&) {};
void inst_counter::visit(const read_flags_event&) {};
void inst_counter::visit(const write_event&) {};
void inst_counter::visit(const write_flags_event&) {};
void inst_counter::visit(const load_event&) {};
void inst_counter::visit(const store_event&) {};

void inst_counter::visit(const operation_event& e) {
    typedef map_type::iterator iterator;
    iterator i(pimpl->map.find(e.opcode()));
    if (i == boost::end(pimpl->map)) {
        pimpl->map[e.opcode()] = 1;
    } else {
        i->second += 1;
    }
}

inst_counter::~inst_counter() {
    std::ofstream out(pimpl->file.c_str(), std::ofstream::out);
    BOOST_FOREACH(const map_type::value_type& e, pimpl->map) {
        out << OPCODE_StringShort(e.first)
            << " = "
            << e.second
            << std::endl;
    }
    out << "Total = " << pimpl->map.size() << std::endl;
}

} //namespace bpt
