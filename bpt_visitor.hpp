#ifndef BAP_VISITOR_HPP
#define BAP_VISITOR_HPP

#include <boost/noncopyable.hpp>
#include "bpt_fwd.hpp"

namespace bpt {

struct visitor : boost::noncopyable {
    virtual void visit(const event&) = 0;
    virtual void visit(const modload_event&);
    virtual void visit(const syscall_event&);
    virtual void visit(const operation_event&);
    virtual void visit(const register_event&);
    virtual void visit(const read_event&);
    virtual void visit(const read_flags_event&);
    virtual void visit(const write_event&);
    virtual void visit(const write_flags_event&);
    virtual void visit(const memory_event&);
    virtual void visit(const load_event&);
    virtual void visit(const store_event&);
    virtual ~visitor();
};

} //namespace bpt

#endif //BAP_VISITOR_HPP
