#ifndef BAP_WRITER_TEXT_HPP
#define BAP_WRITER_TEXT_HPP

#include <string>
#include <fstream>
#include "bpt_visitor.hpp"

namespace bpt {

struct writer_text : visitor {
    explicit writer_text(const std::string& file,
                         int argc, char *argv[], char* env[]);
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
private:
    std::ofstream out;
};

} //namespace bpt

#endif //BAP_WRITER_TEXT_HPP
