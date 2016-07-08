#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <set>

#include <boost/range.hpp>
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/foreach.hpp>

#include "bpt.hpp"
#include "bpt_events.hpp"
#include "bpt_args_list.hpp"
#include "bpt_inspection.hpp"
#include "bpt_visitor.hpp"
namespace bpt {


struct buffer {
    typedef boost::tuple<OPCODE, REG> write_info;
    typedef boost::tuple<ADDRINT, UINT32> store_info;
    void add_modload(IMG img);
    void add_syscall(THREADID, const CONTEXT*, SYSCALL_STANDARD);
    void add_operation(const char*, OPCODE, ADDRINT, UINT32, THREADID);
    void add_read(OPCODE, const CONTEXT*, REG);
    void add_load(ADDRINT, UINT32);

    void add_write(OPCODE, const CONTEXT*, REG);
    void add_lazy_write(OPCODE, REG);
    void force_writes(const CONTEXT*);
    void add_lazy_store(ADDRINT, UINT32);
    void force_stores();
    void flush(visitor&);
    const std::vector<write_info>& lazy_writes() const;
private:
    std::vector<event_ptr> events_;
    std::vector<write_info> lazy_writes_;
    std::vector<store_info> lazy_stores_;
};

static void trace_block(BBL, buffer&);
static void trace_instruction(INS, buffer&);
static void trace_operation(INS, buffer&);
static void trace_reads(INS, buffer&);
static void trace_loads(INS, buffer&);
static void trace_writes(INS, buffer&);
static void trace_stores(INS, buffer&);

static VOID callback_operation(buffer*,
                               const char*,
                               OPCODE,
                               const CONTEXT*,
                               ADDRINT, UINT32, THREADID);

static ADDRINT callback_reads(BOOL, buffer*, OPCODE,
                              const CONTEXT*, UINT32, ...);
static VOID callback_loads(buffer*, UINT32, ...);

static VOID callback_writes(buffer*, OPCODE,
                            const CONTEXT*, UINT32, ...);
static VOID callback_lazy_writes(buffer*, OPCODE,
                                 const CONTEXT*, UINT32, ...);
static VOID callback_lazy_stores(buffer*, UINT32, ...);

static buffer buff_;

void trace(TRACE trace, visitor* out) {
    buff_.flush(*out);
    for(BBL b = TRACE_BblHead(trace);
        BBL_Valid(b); b = BBL_Next(b)) {
        trace_block(b, buff_);
    }
}

void fini(INT32 code, visitor* out) {
    buff_.force_stores();
    buff_.flush(*out);
    if (buff_.lazy_writes().size() != 0) {
        std::cerr << "warning: last instruction writes not traced:"
                  << std::endl;
        
    }
}

void modload(IMG img) {
    buff_.add_modload(img);
}

void syscall_entry(THREADID tid, const CONTEXT *ctx,
                   SYSCALL_STANDARD std) {
    buff_.add_syscall(tid, ctx, std);
}

static void trace_block(BBL b, buffer& buff) {
    INS ins = BBL_InsHead(b);
    for(UINT32 i = 0, I = BBL_NumIns(b);
        i < I; ++i, ins = INS_Next(ins)) {
        trace_instruction(ins, buff);
    }
}

static void trace_instruction(INS ins, buffer& buff) {
    trace_operation(ins, buff);
    trace_reads(ins, buff);
    trace_loads(ins, buff);
    trace_writes(ins, buff);
    trace_stores(ins, buff);
}

static void trace_operation(INS ins, buffer& buff) {
#ifdef BPT_DEBUG
    static std::set<std::string> disasms;
    std::string d = INS_Disassemble(ins);
    boost::algorithm::to_upper(d);
    const char* disasm = disasms.insert(d).first->c_str();
#else
    const char* disasm = "N/A";
#endif
    INS_InsertCall(ins,
                   IPOINT_BEFORE, (AFUNPTR)(callback_operation),
                   IARG_PTR, &buff,
                   IARG_PTR, disasm,
                   IARG_UINT32, INS_Opcode(ins),
                   IARG_CONST_CONTEXT,
                   IARG_INST_PTR,
                   IARG_UINT32, INS_Size(ins),
                   IARG_THREAD_ID,
                   IARG_END);
}


static void trace_reads(INS ins, buffer& buff) {
    args_list common;
    common(IARG_PTR, &buff);
    common(IARG_UINT32, INS_Opcode(ins));
    common(IARG_CONST_CONTEXT);

    args_list reads;
    inspect_inst_reads(ins, reads);

    if (INS_IsPredicated(ins)) {
        args_list preds;
        if (INS_HasRealRep(ins))
            preds(IARG_UINT32, INS_RepCountRegister(ins));

        if (INS_RegRContain(ins, REG_AppFlags()))
            preds(IARG_UINT32, REG_AppFlags());

        INS_InsertIfCall(ins, IPOINT_BEFORE,
                         (AFUNPTR)(callback_reads),
                         IARG_EXECUTING,
                         IARG_IARGLIST, common.value(),
                         IARG_UINT32, reads.size(),
                         IARG_IARGLIST, reads.value(),
                         IARG_END);

        INS_InsertThenCall(ins, IPOINT_BEFORE,
                           (AFUNPTR)(callback_reads),
                           IARG_BOOL, true,
                           IARG_IARGLIST, common.value(),
                           IARG_UINT32, preds.size(),
                           IARG_IARGLIST, preds.value(),
                           IARG_END);
    } else {
        if (reads.size() != 0) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                           (AFUNPTR)(callback_reads),
                           IARG_BOOL, true,
                           IARG_IARGLIST, common.value(),
                           IARG_UINT32, reads.size(),
                           IARG_IARGLIST, reads.value(),
                           IARG_END);
        }
    }
}

static void trace_loads(INS ins, buffer& buff) {
    args_list loads;
    inspect_inst_loads(ins, loads);
    if (loads.size() != 0) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                 (AFUNPTR)(callback_loads),
                                 IARG_PTR, &buff,
                                 IARG_UINT32, loads.size(),
                                 IARG_IARGLIST, loads.value(),
                                 IARG_END);
    }
}

static void trace_writes(INS ins, buffer& buff) {
    args_list common;
    common(IARG_PTR, &buff);
    common(IARG_UINT32, INS_Opcode(ins));
    common(IARG_CONST_CONTEXT);

    args_list writes;
    inspect_inst_writes(ins, writes);
    if (writes.size() != 0) {
        if (INS_HasFallThrough(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_AFTER,
                                     (AFUNPTR)(&callback_writes),
                                     IARG_IARGLIST, common.value(),
                                     IARG_UINT32, writes.size(),
                                     IARG_IARGLIST, writes.value(),
                                     IARG_END);
        } else if (INS_IsBranch(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH,
                                     (AFUNPTR)(&callback_writes),
                                     IARG_IARGLIST, common.value(),
                                     IARG_UINT32, writes.size(),
                                     IARG_IARGLIST, writes.value(),
                                     IARG_END);
        } else {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE,
                (AFUNPTR)(&callback_lazy_writes),
                IARG_IARGLIST, common.value(),
                IARG_UINT32, writes.size(),
                IARG_IARGLIST, writes.value(),
                IARG_END);
        }
    }
}

static void trace_stores(INS ins, buffer& buff) {
    args_list stores;
    inspect_inst_stores(ins, stores);
    if (stores.size() != 0) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                 (AFUNPTR)(callback_lazy_stores),
                                 IARG_PTR, &buff,
                                 IARG_UINT32, stores.size(),
                                 IARG_IARGLIST, stores.value(),
                                 IARG_END);
    }
}


static VOID callback_operation(buffer* buff,
                               const char* disasm,
                               OPCODE opcode,
                               const CONTEXT* ctx,
                               ADDRINT addr, UINT32 size,
                               THREADID tid) {
    buff->force_writes(ctx);
    buff->force_stores();
    buff->add_operation(disasm, opcode, addr, size, tid);
}

static ADDRINT callback_reads(BOOL exec, buffer* buff,
                              OPCODE opcode, const CONTEXT* ctx,
                              UINT32 args_count, ...) {
    if (exec) {
        va_list args;
        va_start(args, args_count);
        for (UINT32 i=0; i < args_count; ++i) {
            buff->add_read(opcode, ctx,
                           static_cast<REG>(va_arg(args, UINT32)));
        }
        va_end(args);
    }
    return exec ? 0 : 1;
}

static VOID callback_loads(buffer* buff, UINT32 args_count, ...) {
    va_list args;
    va_start(args, args_count);
    for (UINT32 i=0; i < args_count; i+=2) {
        ADDRINT addr = va_arg(args, ADDRINT);
        UINT32 size = va_arg(args, UINT32);
        buff->add_load(addr, size);
    }
    va_end(args);
}

static VOID callback_writes(buffer* buff,
                            OPCODE opcode, const CONTEXT* ctx,
                            UINT32 args_count, ...) {
    va_list args;
    va_start(args, args_count);
    for (UINT32 i=0; i < args_count; ++i) {
        buff->add_write(opcode, ctx,
                        static_cast<REG>(va_arg(args, UINT32)));
    }
    va_end(args);
}

static VOID callback_lazy_writes(buffer* buff,
                                 OPCODE opcode, const CONTEXT* ctx,
                                 UINT32 args_count, ...) {
    va_list args;
    va_start(args, args_count);
    for (UINT32 i=0; i < args_count; ++i) {
        buff->add_lazy_write(opcode,
                             static_cast<REG>(va_arg(args, UINT32)));
    }
    va_end(args);
}

static VOID callback_lazy_stores(buffer* buff,
                                 UINT32 args_count, ...) {
    va_list args;
    va_start(args, args_count);
    for (UINT32 i=0; i < args_count; i+=2) {
        ADDRINT addr = va_arg(args, ADDRINT);
        UINT32 size = va_arg(args, UINT32);
        buff->add_lazy_store(addr, size);
    }
    va_end(args);
}

void buffer::add_modload(IMG img) {
    events_.push_back(event_ptr(new modload_event(img)));
}

void buffer::add_syscall(THREADID tid, const CONTEXT* ctx,
                         SYSCALL_STANDARD std) {
    events_.push_back(event_ptr(new syscall_event(tid, ctx, std)));
}

void buffer::add_operation(const char* disasm, OPCODE opcode,
                           ADDRINT addr, UINT32 size, THREADID tid) {
    events_.push_back(
        event_ptr(new operation_event(disasm, opcode,
                                      addr, size, tid)));
}

void buffer::add_read(OPCODE opcode, const CONTEXT* ctx, REG reg) {
    events_.push_back(
        event_ptr(REG_is_flags(reg) ?
                  new read_flags_event(opcode, reg, ctx) :
                  new read_event(opcode, reg, ctx)));

}

void buffer::add_load(ADDRINT addr, UINT32 size) {
    events_.push_back(event_ptr(new load_event(addr, size)));
}

void buffer::add_write(OPCODE opcode, const CONTEXT* ctx, REG reg) {
    events_.push_back(
        event_ptr(REG_is_flags(reg) ?
                  new write_flags_event(opcode, reg, ctx) :
                  new write_event(opcode, reg, ctx)));
}

void buffer::add_lazy_write(OPCODE opcode, REG reg) {
    lazy_writes_.push_back(boost::make_tuple(opcode, reg));
}

void buffer::force_writes(const CONTEXT* ctx) {
    BOOST_FOREACH( write_info info, lazy_writes_) {
        add_write(boost::get<0>(info), ctx, boost::get<1>(info));
    }
    lazy_writes_.clear();
}

void buffer::add_lazy_store(ADDRINT addr, UINT32 size) {
    lazy_stores_.push_back(boost::make_tuple(addr, size));
}
void buffer::force_stores() {
    BOOST_FOREACH(store_info info, lazy_stores_) {
        events_.push_back(
            event_ptr(new store_event(boost::get<0>(info),
                                      boost::get<1>(info))));
    }
    lazy_stores_.clear();
}

void buffer::flush(visitor& out) {
    std::for_each(boost::begin(events_),
                  boost::end(events_),
                  boost::bind(&event::accept, _1, boost::ref(out)));
    events_.clear();
}

const std::vector<buffer::write_info>& buffer::lazy_writes() const {
    return lazy_writes_;
}

} //namespace bpt

