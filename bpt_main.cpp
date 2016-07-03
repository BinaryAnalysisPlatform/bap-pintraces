#include <fstream>
#include <iostream>
#include <pin.H>
#include "bpt.hpp"
#include "bpt_inst_counter.hpp"
#include "bpt_writer_text.hpp"
#include "bpt_writer_frames.hpp"

KNOB<string> tracefile(KNOB_MODE_WRITEONCE, "pintool",
                       "o", "trace.frames",
                       "Trace file to output to "
                       "(filename.{frames | txt | cnt})");

INT32 usage() {
    PIN_ERROR( "This Pintool trace "
               "instructions memory and registers usage\n"
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

VOID fini(INT32 code, VOID* ptr) {
    bpt::visitor* out = static_cast<bpt::visitor*>(ptr);
    bpt::fini(code, out);
    delete out;
}

VOID trace(TRACE trace, VOID* ptr) {
    bpt::visitor* out = static_cast<bpt::visitor*>(ptr);
    bpt::trace(trace, out);
}

VOID modload(IMG img, VOID*) {
    bpt::modload(img);
}

VOID syscall_entry(THREADID tid, CONTEXT* ctx,
                   SYSCALL_STANDARD std, VOID*) {
    bpt::syscall_entry(tid, ctx, std);
}

extern char** environ;

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return usage();
    bpt::visitor* out;    
    std::string file = tracefile.Value();
    std::string fmt = file.substr(file.find_last_of(".") + 1);
    if (fmt == "txt") {
        out = new bpt::writer_text(file.c_str(), argc, argv, environ);
    } else if (fmt == "frames") {
        out = new bpt::writer_frames(file.c_str(), argc, argv, environ);
    } else if (fmt == "cnt") {
        out = new bpt::inst_counter(file.c_str());
    } else {
        std::cerr << "unknown trace format " << fmt << std::endl;
        exit(0);
    }

    TRACE_AddInstrumentFunction(trace, static_cast<VOID*>(out));
    IMG_AddInstrumentFunction(modload, 0);
    PIN_AddFiniFunction(fini, static_cast<VOID*>(out));
    PIN_AddSyscallEntryFunction(syscall_entry, 0);
    PIN_StartProgram();
    return 0;
}
