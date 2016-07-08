#ifndef BPT_BYTES_IO_HPP
#define BPT_BYTES_IO_HPP

#include <iostream>
#include <pin.H>

#include "bpt_fwd.hpp"

namespace bpt { namespace io {
bytes_type from_reg(REG, const CONTEXT*);
bytes_type from_mem(ADDRINT, UINT32);

std::ostream& pp_addr(std::ostream&, ADDRINT);

namespace code {
std::ostream& operator<<(std::ostream&, const bytes_type&);
}

namespace data {
std::ostream& operator<<(std::ostream&, const bytes_type&);
}

}} //namespace bpt::io

#endif //BPT_BYTES_IO_HPP
