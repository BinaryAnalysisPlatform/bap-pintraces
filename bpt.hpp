#ifndef BPT_HPP
#define BPT_HPP

#include <pin.H>
#include "bpt_fwd.hpp"

namespace bpt {

void trace(TRACE, visitor*);
void fini(INT32 code, visitor*);
void modload(IMG);
void syscall_entry(THREADID, const CONTEXT*, SYSCALL_STANDARD);

}

#endif //BPT_HPP
