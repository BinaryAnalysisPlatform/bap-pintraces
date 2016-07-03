#include <iomanip>
#include <iostream>
#include <numeric>
#include <algorithm>
#include <functional>

#include <boost/algorithm/string.hpp>
#include "bpt_events.hpp"

namespace bpt {

void event::accept(visitor& out) { do_accept(out); }
event::~event() {}

std::ostream& operator<<(std::ostream& out, const event& e) {
    return e.operator<<(out);
}

} //namespace bpt
