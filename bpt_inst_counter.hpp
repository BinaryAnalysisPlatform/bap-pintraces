#ifndef BAP_INST_COUNTER_HPP
#define BAP_INST_COUNTER_HPP

#include <string>
#include <boost/shared_ptr.hpp>
#include "bpt_visitor.hpp"

namespace bpt {

struct inst_counter : visitor {
    explicit inst_counter(const std::string& file);
    virtual void visit(const event&);
    virtual void visit(const modload_event&);
    virtual void visit(const syscall_event&);
    virtual void visit(const operation_event&);
    virtual void visit(const read_event&);
    virtual void visit(const read_flags_event&);
    virtual void visit(const write_event&);
    virtual void visit(const write_flags_event&);
    virtual void visit(const load_event&);
    virtual void visit(const store_event&);
    virtual ~inst_counter();
private:
    struct impl;
    boost::shared_ptr<impl> pimpl;
};

} //namespace bpt

#endif //BAP_INST_COUNTER_HPP
