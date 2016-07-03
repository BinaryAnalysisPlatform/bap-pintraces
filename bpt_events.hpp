#ifndef BPT_EVENTS_HPP
#define BTP_EVENTS_HPP

#include <vector>
#include <string>

#include <boost/shared_ptr.hpp>

#include <pin.H>

#include "bpt_fwd.hpp"

namespace bpt {

struct event {
    void accept(visitor&);
    virtual ~event();
    virtual std::ostream& operator<<(std::ostream&) const = 0;
private:
    virtual void do_accept(visitor&) const = 0;
};

std::ostream& operator<<(std::ostream&, const event&);

struct operation_event : event {
    operation_event(const char*, OPCODE, ADDRINT, UINT32, THREADID);
    OPCODE opcode() const;
    ADDRINT addr() const;
    THREADID tid() const;
    std::string name() const;
    const bytes_type& bytes() const;
    const char* disasm() const;
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
    struct impl;
    boost::shared_ptr<impl> pimpl;
};

struct register_event : event {
    register_event(OPCODE, REG, const CONTEXT*);
    const bytes_type& bytes() const;
    std::size_t width() const;
    std::string name() const;
    OPCODE opcode() const;
private:
    struct impl;
    boost::shared_ptr<impl> pimpl;
};

struct memory_event : event {
    memory_event(ADDRINT addr, UINT32 size);
    const bytes_type& bytes() const;
    ADDRINT addr() const;
private:
    struct impl;
    boost::shared_ptr<impl> pimpl;
};

struct read_event : register_event {
    read_event(OPCODE, REG, const CONTEXT*);
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
};

struct write_event : register_event {
    write_event(OPCODE, REG, const CONTEXT*);
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
};

typedef int effect_type;
const effect_type NONE = 0;
const effect_type CLR = 1; //The flag is always cleared to 0.
const effect_type SET = 2; //The flag is always set to 1.
const effect_type AH = 4; //The flag is loaded with value from AH register
const effect_type MOD = 8; //The flag is modified, depending on the results of the instruction.
const effect_type POP = 16; //The flag is loaded with value popped off of the stack.
const effect_type TST = 32; //The flag is tested.
const effect_type UND = 64; //The effect on the flag is undefined.
const effect_type RD = TST;
const effect_type WR = CLR | SET | AH | MOD | POP | UND;

namespace RFLAGS {
struct field;
typedef boost::shared_ptr<field> field_ptr;
}

struct flag {
    flag(const RFLAGS::field_ptr&, effect_type);
    const std::string& name() const;
    effect_type effect() const;
    std::size_t width() const;
    bytes_type::value_type value(const bytes_type&) const;
private:
    const RFLAGS::field_ptr field;
    effect_type mask;
};

typedef std::vector<flag> flags_type;
struct read_flags_event : read_event {
    read_flags_event(OPCODE, REG, const CONTEXT*);
    const flags_type& flags() const;
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
};

struct write_flags_event : write_event {
    write_flags_event(OPCODE, REG, const CONTEXT*);
    const flags_type& flags() const;
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
};

struct load_event : memory_event {
    load_event(ADDRINT addr, UINT32 size);
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
};

struct store_event : memory_event {
    store_event(ADDRINT addr, UINT32 size);
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
};

struct modload_event : event {
    explicit modload_event(IMG img);
    const std::string& name() const;
    ADDRINT high() const;
    ADDRINT low() const;
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
    struct impl;
    boost::shared_ptr<impl> pimpl;
};

struct syscall_event : event {
    syscall_event(THREADID, const CONTEXT*, SYSCALL_STANDARD);
    ADDRINT addr() const;
    THREADID tid() const;
    ADDRINT number() const;
    const std::vector<ADDRINT>& args() const;
    virtual std::ostream& operator<<(std::ostream&) const;
private:
    virtual void do_accept(visitor&) const;
    struct impl;
    boost::shared_ptr<impl> pimpl;
};

} //namespace bpt

#endif //BPT_EVENTS_HPP
