#ifndef BPT_INSPECTION_HPP
#define BPT_INSPECTION_HPP

#include <pin.H>

namespace bpt {

class args_list;
void inspect_inst_reads(INS, args_list&);
void inspect_inst_writes(INS, args_list&);
void inspect_inst_loads(INS, args_list&);
void inspect_inst_stores(INS, args_list&);

} //namespace pbt

#endif //BPT_INSPECTION_HPP
