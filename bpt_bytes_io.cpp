#include <iomanip>
#include <iostream>
#include <algorithm>
#include <functional>
#include <numeric>

#include "bpt_bytes_io.hpp"

namespace bpt { namespace io {

template <typename T1, typename T2>
T1 pointer_cast(T2* ptr) {
    return static_cast<T1>(static_cast<void*>(ptr));
}

bytes_type from_reg(REG reg, const CONTEXT* ctx) {
    bytes_type data(REG_Size(reg));
    PIN_GetContextRegval(ctx, reg,
                         pointer_cast<UINT8*>(&data[0]));
    return data;
}

bytes_type from_mem(ADDRINT addr, UINT32 size) {
    bytes_type data(size);
    PIN_SafeCopy(static_cast<VOID*>(&data[0]),
                 reinterpret_cast<VOID*>(addr), size);
    return data;
}

struct ios_flag_saver {
    explicit ios_flag_saver(std::ostream& os)
        : os_(os), f_(os.flags()) {}
    ~ios_flag_saver() { os_.flags(f_); }
private:
    std::ostream& os_;
    std::ios::fmtflags f_;
};

struct bytes_printer : std::binary_function<const std::string&,
                                            char,
                                            std::string> {
    bytes_printer(std::ostream& o, const std::string& s)
        : out(o), sep(s) {}
    std::string operator()(const std::string& init, char b) {
        ios_flag_saver s(out);
        out << init
            << std::hex
            << std::uppercase
            << std::setfill('0')
            << std::setw(2)
            << static_cast<int>(static_cast<unsigned char>(b));
        return sep;
    }
private:
    std::ostream& out;
    const std::string& sep;
};

std::ostream& pp_addr(std::ostream& out, ADDRINT addr) {
    return out << "0x" << std::hex << addr << std::dec
               << ':' << sizeof(ADDRINT)*8;
}

std::ostream& code::operator<<(std::ostream& out,
                               const bytes_type& bytes) {
    std::accumulate(bytes.begin(), bytes.end(),
                    std::string(""), bytes_printer(out, " "));
    return out;
}

std::ostream& data::operator<<(std::ostream& out,
                               const bytes_type& data) {
    bytes_type::const_reverse_iterator it =
        std::find_if(data.rbegin(), data.rend(),
                     std::bind1st(std::not_equal_to<char>(), 0));
    if (it != data.rend()) {
        out << "0x";
        std::accumulate(it, data.rend(),
                        std::string(""), bytes_printer(out, ""));
    } else {
        out << "0x0";
    }
    return out;
}
}} //namespace bpt::io
