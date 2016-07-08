#ifndef BPT_ARG_LIST_HPP
#define BPT_ARG_LIST_HPP

#include <boost/noncopyable.hpp>

#include <pin.H>

namespace bpt {

struct args_list : boost::noncopyable {
    explicit args_list();
    ~args_list();

    args_list& operator()(IARG_TYPE);

    template <typename T>
    args_list& operator()(IARG_TYPE, T);

    template <typename T1, typename T2>
    args_list& operator()(IARG_TYPE, T1, IARG_TYPE, T2);

    IARGLIST value();
    UINT32 size();
private:
    IARGLIST list_;
    UINT32 size_;
};

template <typename T>
args_list& args_list::operator()(IARG_TYPE typ, T val) {
    IARGLIST_AddArguments(list_, typ, val, IARG_END);
    ++size_;
    return *this;
}

template <typename T1, typename T2>
args_list& args_list::operator()(IARG_TYPE typ1, T1 val1,
                                 IARG_TYPE typ2, T2 val2) {
    IARGLIST_AddArguments(list_, typ1, val1, typ2, val2, IARG_END);
    size_ += 2;
    return *this;

}

} //namespace bpt

#endif //BPT_ARG_LIST_HPP
