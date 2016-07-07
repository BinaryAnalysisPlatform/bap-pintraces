#include "bpt_writer_text.hpp"
#include "bpt_events.hpp"

namespace bpt {
writer_text::writer_text(const std::string& file,
                         int argc, char* argv[], char* env[])
    : out(file.c_str(), std::ofstream::out) {
    for (int i=0; i < argc; ++i) {
        out << argv[i];
    }
    out << std::endl;
    while(*env) {
        out << *env++ << std::endl;
    }
}

void writer_text::visit(const event& e) {
    out << e << std::endl;
}

void writer_text::visit(const modload_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const syscall_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const operation_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const read_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const write_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const read_flags_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const write_flags_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const load_event& e) {
    out << e << std::endl;
}

void writer_text::visit(const store_event& e) {
    out << e << std::endl;
}

} //namespace bpt
