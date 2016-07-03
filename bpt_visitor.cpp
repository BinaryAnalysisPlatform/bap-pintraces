#include "bpt_visitor.hpp"
#include "bpt_events.hpp"

namespace bpt {

void visitor::visit(const modload_event& e) {
    visit(static_cast<const event&>(e));
}

void visitor::visit(const syscall_event& e) {
    visit(static_cast<const event&>(e));
}

void visitor::visit(const operation_event& e) {
    visit(static_cast<const event&>(e));
}

void visitor::visit(const register_event& e) {
    visit(static_cast<const event&>(e));
}

void visitor::visit(const memory_event& e) {
    visit(static_cast<const event&>(e));
}

void visitor::visit(const read_event& e) {
    visit(static_cast<const register_event&>(e));
}

void visitor::visit(const write_event& e) {
    visit(static_cast<const register_event&>(e));
}

void visitor::visit(const read_flags_event& e) {
    visit(static_cast<const read_event&>(e));
}

void visitor::visit(const write_flags_event& e) {
    visit(static_cast<const write_event&>(e));
}

void visitor::visit(const load_event& e) {
    visit(static_cast<const memory_event&>(e));
}

void visitor::visit(const store_event& e) {
    visit(static_cast<const memory_event&>(e));
}

visitor::~visitor() {}

}
