#include "bpt_args_list.hpp"
namespace bpt {

args_list::args_list() : list_(IARGLIST_Alloc()), size_(0) {}
args_list::~args_list() { IARGLIST_Free(list_); }

args_list& args_list::operator()(IARG_TYPE typ) {
    IARGLIST_AddArguments(list_, typ, IARG_END);
    ++size_;
    return *this;
}

UINT32 args_list::size() { return size_; }
IARGLIST args_list::value() { return list_; }

} //namespace bpt
