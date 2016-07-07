#include <string>
#include <stdexcept>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

#include <boost/range.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/bind.hpp>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>

#include <libtrace/trace.container.hpp>

#include "bpt_writer_frames.hpp"
#include "bpt_events.hpp"

namespace bpt {

namespace proto = SerializedTrace;
typedef proto::TraceContainerWriter container_type;

inline std::string string_of_bytes(const bytes_type& bytes) {
    return std::string(boost::begin(bytes), boost::end(bytes));
}

struct std_frame_element : boost::noncopyable {
    enum usage {R, W};
    std_frame_element(container_type& c,
                      const operation_event& op)
        : cont(c) {
        ::std_frame* sf = frm.mutable_std_frame();
        sf->set_address(op.addr());
        sf->set_thread_id(op.tid());
        sf->set_rawbytes(string_of_bytes(op.bytes()));
        static_cast<void>(sf->mutable_operand_pre_list());
        static_cast<void>(sf->mutable_operand_post_list());
    }

    void add(const read_event& e) { add(R, e); }
    void add(const write_event& e) { add(W, e); }
    void add(const load_event& e) { add(R, e); }
    void add(const store_event& e) { add(W, e); }
    void add(const read_flags_event& e) {
        BOOST_FOREACH(const flag& f, e.flags()) {
            if (f.effect() & RD) {
                bytes_type::value_type b(f.value(e.bytes()));
                add(R, f.name(), bytes_type(1, b), f.width());
            }
        }
    }
    void add(const write_flags_event& e) {
        BOOST_FOREACH(const flag& f, e.flags()) {
            if (f.effect() & WR) {
                bytes_type::value_type b(f.value(e.bytes()));
                add(W, f.name(), bytes_type(1, b), f.width());
            }
        }
    }

    void finish() {
        cont.add(frm);
    }

private:
    void add(usage u, const register_event& e) {
        add(u, e.name(), e.bytes(), e.width()); 
    }

    void add(usage u, const memory_event& e) {
        add(u, e.addr(), e.bytes());
    }

    void add(usage u, ADDRINT addr, const bytes_type& data) {
        ::operand_info_specific* ois = create_operand(u, data);
        ::mem_operand* mo = ois->mutable_mem_operand();
        mo->set_address(addr);
    }

    void add(usage u, const std::string& name,
                     const bytes_type& data, int width) {
        ::operand_info_specific* ois = create_operand(u, data, width);
        ::reg_operand* ro = ois->mutable_reg_operand();
        ro->set_name(name);
    }

    ::operand_info_specific* create_operand(usage u,
                                            const bytes_type& data,
                                            int width = 0) {
        ::std_frame* sf = frm.mutable_std_frame();
        ::operand_value_list* ovl = 0;
        switch(u) {
        case R: ovl = sf->mutable_operand_pre_list(); break;
        case W: ovl = sf->mutable_operand_post_list(); break;
        }
        ::operand_info* oi = ovl->add_elem();
        oi->set_bit_length(width == 0 ? 8*data.size() : width);
        ::operand_usage* ou = oi->mutable_operand_usage();
        ou->set_read(u == R);
        ou->set_written(u == W);
        ou->set_index(false);
        ou->set_base(false);
        oi->set_value(std::string(data.begin(), data.end()));
        oi->mutable_taint_info()->set_no_taint(true);
        return oi->mutable_operand_info_specific();
    }

private:
    container_type& cont;
    ::frame frm;
};

static const frame_architecture arch = frame_arch_i386;
#if defined(TARGET_IA32)
    static const uint64_t machine = frame_mach_i386_i386;
#elif defined(TARGET_IA32E)
    static const uint64_t machine = frame_mach_x86_64;
#else
#error "Usupported machine"
#endif

namespace meta {
template <typename T>
void init_data(T* obj, void (T::*fn)(const char*), char* data[]) {
    while(*data) {
        (obj->*fn)(*data++);
    }
}

void init_tracer(::tracer* tracer,
                 int argc, char* argv[], char* envp[]) {
    tracer->set_name("bpt");
    init_data(tracer, &::tracer::add_args, argv);
    init_data(tracer, &::tracer::add_envp, envp);
    tracer->set_version("1.0.0");
}

std::string md5sum(const std::string& path) {
    std::string md5;
    CryptoPP::Weak::MD5 hash;
    CryptoPP::FileSource(
        path.c_str(), true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(md5)));
    return md5;
}

void init_target(::target* target, const std::string& path,
                 int argc, char* argv[], char* envp[]) {
    target->set_path(path);
    init_data(target, &::target::add_args, argv);
    init_data(target, &::target::add_envp, envp);
    target->set_md5sum(md5sum(path));
}

void init_fstats(::fstats* fstats, const std::string& path) {
    struct stat stats;
    if (stat(path.c_str(), &stats) < 0)
        throw std::runtime_error("failed to obtain file stats");

    fstats->set_size(stats.st_size);
    fstats->set_atime(stats.st_atime);
    fstats->set_mtime(stats.st_mtime);
    fstats->set_ctime(stats.st_ctime);
}

::meta_frame create(int argc, char* argv[], char* envp[]) {
    ::meta_frame meta;
    int dpos = argc;
    for (int i = 0; i < argc; ++i) {
        if (std::string("--") == argv[i]) {
            dpos = i;
            break;
        }
    }
    namespace fs = boost::filesystem;
    fs::path path(argv[dpos + 1]);
    if (path.is_relative()) {
        if (fs::exists(path)) {
            path = fs::absolute(path);
        } else if (path.parent_path().empty()) {
            std::string PATH(::getenv("PATH"));
            std::vector<std::string> roots;
            boost::split(roots, PATH, boost::is_any_of(":;"));
            typedef std::vector<std::string>::iterator iterator_type;
            for (iterator_type root = boost::begin(roots);
                 root != boost::end(roots); ++root) {
                fs::path absolute_path = fs::absolute(path, *root);
                if (fs::exists(absolute_path)) {
                    path = absolute_path;
                    break;
                }
            }
        }
    }
    if (! fs::exists(path) ) {
        throw std::invalid_argument(path.string() + " not found");
    }
    init_tracer(meta.mutable_tracer(), dpos, argv, envp);
    init_target(meta.mutable_target(), path.string(),
                      argc - dpos - 1, argv + dpos + 1, envp);
    init_fstats(meta.mutable_fstats(), path.string());
    meta.set_user(::getlogin());
    char host[1024];
    ::gethostname(host, sizeof(host));
    meta.set_host(host);
    meta.set_time(::time(0));
    return meta;
}
} //namespace meta

struct writer_frames::impl {
    explicit impl(const std::string& file, int argc, char* argv[],
                  char* envp[])
        : cont (file, meta::create(argc, argv, envp), arch, machine) {
    }

    ~impl() {
        try {
            if (std_frame) std_frame->finish();
            cont.finish();
        } catch (std::exception& e) {
            std::cerr << "finish failed with:" << e.what() << std::endl;
        }
    }
    container_type cont;
    boost::scoped_ptr<std_frame_element> std_frame;

};

writer_frames::writer_frames(const std::string& file,
                             int argc, char* argv[], char* env[])
    : pimpl(new impl(file, argc, argv, env)) {}

void writer_frames::visit(const event& e) {
    std::cerr << "warning: skipped event "
              << e
              << " in frames protocol"
              << std::endl;
}

void writer_frames::visit(const modload_event& e) {
    ::frame frm;
    ::modload_frame* mf = frm.mutable_modload_frame();
    mf->set_module_name(e.name());
    mf->set_low_address(e.low());
    mf->set_high_address(e.high());
    pimpl->cont.add(frm);
}

void writer_frames::visit(const syscall_event& e) {
    ::frame frm;
    ::syscall_frame* f = frm.mutable_syscall_frame();
    f->set_address(e.addr());
    f->set_thread_id(e.tid());
    f->set_number(e.number());
    ::argument_list* args = f->mutable_argument_list();
    BOOST_FOREACH(ADDRINT addr, e.args()) {
        args->add_elem(addr);
    }
    pimpl->cont.add(frm);
}

void writer_frames::visit(const operation_event& e) {
    if (pimpl->std_frame)
        pimpl->std_frame->finish();
    pimpl->std_frame.reset(new std_frame_element(pimpl->cont, e));
}

void writer_frames::visit(const read_event& e) {
    pimpl->std_frame->add(e);
}

void writer_frames::visit(const read_flags_event& e) {
    pimpl->std_frame->add(e);
}

void writer_frames::visit(const write_event& e) {
    pimpl->std_frame->add(e);
}

void writer_frames::visit(const write_flags_event& e) {
    pimpl->std_frame->add(e);
}

void writer_frames::visit(const load_event& e) {
    pimpl->std_frame->add(e);
}

void writer_frames::visit(const store_event& e) {
    pimpl->std_frame->add(e);
}

} //namespace bpt
