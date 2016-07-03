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
private:
    std::ofstream out;
};

} //namespace bpt

#endif //BAP_WRITER_TEXT_HPP
