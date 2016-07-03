#ifndef BAP_INST_COUNTER_HPP
#define BAP_INST_COUNTER_HPP

#include <string>
#include <boost/shared_ptr.hpp>
#include "bpt_visitor.hpp"

namespace bpt {

struct inst_counter : visitor {
    explicit inst_counter(const std::string& file);
    virtual void visit(const event&);
    virtual void visit(const operation_event&);
    virtual ~inst_counter();
private:
    struct impl;
    boost::shared_ptr<impl> pimpl;
};

} //namespace bpt

#endif //BAP_INST_COUNTER_HPP
