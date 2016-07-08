#ifndef BAP_VISITOR_HPP
#define BAP_VISITOR_HPP

#include <boost/noncopyable.hpp>
#include "bpt_fwd.hpp"

namespace bpt {

struct visitor : boost::noncopyable {
    virtual void visit(const event&) = 0;
    virtual void visit(const modload_event&) = 0;
    virtual void visit(const syscall_event&) = 0;
    virtual void visit(const operation_event&) = 0;
    virtual void visit(const read_event&) = 0;
    virtual void visit(const read_flags_event&) = 0;
    virtual void visit(const write_event&) = 0;
    virtual void visit(const write_flags_event&) = 0;
    virtual void visit(const load_event&) = 0;
    virtual void visit(const store_event&) = 0;
    virtual ~visitor() {};
};

} //namespace bpt

#endif //BAP_VISITOR_HPP
