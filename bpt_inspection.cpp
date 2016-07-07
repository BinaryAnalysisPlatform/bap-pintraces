#include <iostream>
#include <set>

#include <boost/foreach.hpp>

#include "bpt_args_list.hpp"
#include "bpt_inspection.hpp"

namespace bpt {

static void inspect_inst_reads(INS ins, std::set<REG>& reads) {
    for (UINT32 i = 0, I = INS_OperandCount(ins); i < I; ++i) {
        if (INS_OperandIsReg(ins, i)) {
            REG reg = INS_OperandReg(ins, i);
            REG base = REG_FullRegName(reg);
            if (INS_OperandRead(ins, i)) reads.insert(base);
            /* This is special case handle writes to partial registers,
               when the rest part of base register stays unchanged.*/
            if (INS_OperandWritten(ins, i) &&
                REG_is_partialreg(reg) &&
                !REG_is_gr32(reg)) reads.insert(base);
        }

        if (INS_OperandIsMemory(ins, i) ||
            INS_OperandIsAddressGenerator(ins, i)) {
            REG seg = INS_OperandMemorySegmentReg(ins, i);
            switch (seg) {
            case REG_SEG_FS: reads.insert(REG_SEG_FS_BASE); break;
            case REG_SEG_GS: reads.insert(REG_SEG_GS_BASE); break;
            default:
                if (REG_valid(seg)) {
                    std::cerr << "warning: untraceable segment "
                              << REG_StringShort(seg)
                              << "in instruction "
                              << INS_Disassemble(ins)
                              << std::endl;
                }
            }

            REG base = INS_OperandMemoryBaseReg(ins, i);
            reads.insert(REG_FullRegName(base));
            REG index = INS_OperandMemoryIndexReg(ins, i);
            reads.insert(REG_FullRegName(index));
        }
    }
    reads.erase(REG_INVALID());
    reads.erase(REG_INST_PTR);
}

static void inspect_inst_writes(INS ins, std::set<REG>& writes) {
    for (UINT32 i = 0, I = INS_OperandCount(ins); i < I; ++i) {
        if (INS_OperandIsReg(ins, i) &&
            INS_OperandWritten(ins, i)) {
            REG reg = INS_OperandReg(ins, i);
            writes.insert(REG_FullRegName(reg));
        }

        if (INS_OperandIsMemory(ins, i) ||
            INS_OperandIsAddressGenerator(ins, i)) {
            REG base = INS_OperandMemoryBaseReg(ins, i);
            if (INS_RegWContain(ins, base)) {
                writes.insert(REG_FullRegName(base));
            }
            REG index = INS_OperandMemoryIndexReg(ins, i);
            if (INS_RegWContain(ins, index)) {
                writes.insert(REG_FullRegName(index));
            }
        }
    }
    writes.erase(REG_INVALID());
    writes.erase(REG_INST_PTR);
}


static void copy(args_list& args, const std::set<REG>& set) {
    BOOST_FOREACH(REG reg, set) {
        args(IARG_UINT32, reg);
    }
}

void inspect_inst_reads(INS ins, args_list& reads) {
    std::set<REG> regs;
    inspect_inst_reads(ins, regs);
    copy(reads, regs);
}

void inspect_inst_writes(INS ins, args_list& writes) {
    std::set<REG> regs;
    inspect_inst_writes(ins, regs);
    copy(writes, regs);
}

void inspect_inst_loads(INS ins, args_list& loads) {
    for (UINT32 i = 0, I = INS_MemoryOperandCount(ins); i < I; ++i) {
        if (INS_MemoryOperandIsRead(ins, i)) {
            loads(IARG_MEMORYOP_EA, i,
                  IARG_UINT32, INS_MemoryReadSize(ins));
        }
    }
}

void inspect_inst_stores(INS ins, args_list& stores) {
    for (UINT32 i = 0, I = INS_MemoryOperandCount(ins); i < I; ++i) {
        if (INS_MemoryOperandIsWritten(ins, i)) {
            stores(IARG_MEMORYOP_EA, i,
                   IARG_UINT32, INS_MemoryWriteSize(ins));
        }
    }
}

} //namespace bpt
