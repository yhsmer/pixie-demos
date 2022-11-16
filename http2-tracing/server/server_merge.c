#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/fdtable.h>
#include <net/inet_sock.h>

// --------------------------------------------- macro Begin ---------------------------------------------
#ifdef memset
#undef memset
#endif
#define memset __builtin_memset

// 将_val定义成P指向的类型, typeof获取类型
#define _READ(P) ({                          \
    typeof(P) _val;                          \
    memset(&_val, 0, sizeof(_val));          \
    bpf_probe_read(&_val, sizeof(_val), &P); \
    _val;                                    \
})

#define MAX_HEADER_COUNT 64
#define HEADER_FIELD_STR_SIZE 128
// 一种将数据存储在环形缓冲区中的BPF映射
BPF_PERF_OUTPUT(go_grpc_events);
// --------------------------------------------- macro End   ---------------------------------------------

// --------------------------------------------- Struct Begin ---------------------------------------------
struct go_interface
{
    int64_t type;
    void *ptr;
};

enum location_type_t
{
    kLocationTypeInvalid = 0,
    kLocationTypeStack = 1,
    kLocationTypeRegisters = 2
};

struct location_t
{
    enum location_type_t type;
    int32_t offset;
};

struct go_regabi_regs
{
    uint64_t regs[9];
};

struct header_field_t
{
    int32_t size;
    char msg[HEADER_FIELD_STR_SIZE];
};

struct go_grpc_http2_header_event_t
{
    struct header_field_t name;
    struct header_field_t value;
};

// This matches the golang string object memory layout. Used to help read golang string objects in BPF code.
struct gostring
{
    const char *ptr;
    int64_t len;
};

struct go_grpc_framer_t
{
    void *writer;
    void *http2_framer;
};

// The BPF map used to store the registers of Go's register-based calling convention.
BPF_PERCPU_ARRAY(regs_heap, struct go_regabi_regs, 1);

struct grpc_event
{
    // client(1) server(2) unknown(4)
    int trace_role;
    u32 pid;
    u32 tgid;
    int fd;
    u32 stream_id;
    u64 remote_ip;
    int remote_port;
    char content_type[30];
    char req_method[10];
    char req_path[50];
    char req_status[10];
    int req_body_size;
    int reqsp_body_size;
    u64 timestamp_ns;
    int name_size;
    char name_msg[HEADER_FIELD_STR_SIZE];
    int value_size;
    char value_msg[HEADER_FIELD_STR_SIZE];
    char probe_type[50];
};

// 创建数组映射，参数分别为name, value类型（key为数组下标），元素个数
// 数组映射元素不可删除，只能更新
BPF_PERCPU_ARRAY(header_event_buffer_heap, struct grpc_event, 1);
static __inline struct grpc_event *get_header_event()
{
    uint32_t kZero = 0;
    struct grpc_event *event = header_event_buffer_heap.lookup(&kZero);
    if (event == NULL)
    {
        return NULL;
    }
    memset(event, 0, sizeof(*event));
    return event;
    //   return header_event_buffer_heap.lookup(&kZero);
}

// --------------------------------------------- Struct End   ---------------------------------------------

// --------------------------------------------- Assist Function Begin ---------------------------------------------
// Reads a golang function argument, taking into account the ABI.
// Go arguments may be in registers or on the stack.
static __inline void assign_arg(void *arg, size_t arg_size, struct location_t loc, const void *sp, uint64_t *regs)
{
    if (loc.type == kLocationTypeStack)
    {
        bpf_probe_read(arg, arg_size, sp + loc.offset);
    }
    else if (loc.type == kLocationTypeRegisters)
    {
        if (loc.offset >= 0)
        {
            bpf_probe_read(arg, arg_size, (char *)regs + loc.offset);
        }
    }
}

// Copies the registers of the golang ABI, so that they can be
// easily accessed using an offset.
static __inline uint64_t *go_regabi_regs(const struct pt_regs *ctx)
{
    struct go_regabi_regs regs_heap;

    struct go_regabi_regs *regs_heap_var = &regs_heap;
    regs_heap_var->regs[0] = ctx->ax;
    regs_heap_var->regs[1] = ctx->bx;
    regs_heap_var->regs[2] = ctx->cx;
    regs_heap_var->regs[3] = ctx->di;
    regs_heap_var->regs[4] = ctx->si;
    regs_heap_var->regs[5] = ctx->r8;
    regs_heap_var->regs[6] = ctx->r9;
    regs_heap_var->regs[7] = ctx->r10;
    regs_heap_var->regs[8] = ctx->r11;

    return regs_heap_var->regs;
}

static __always_inline struct file *bpf_fget(int fd)
{
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    int max_fds;
    struct file **fds;
    struct file *fil;

    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return NULL;

    files = _READ(task->files);
    if (!files)
        return NULL;

    fdt = _READ(files->fdt);
    if (!fdt)
        return NULL;

    max_fds = _READ(fdt->max_fds);
    if (fd >= max_fds)
        return NULL;

    fds = _READ(fdt->fd);
    fil = _READ(fds[fd]);

    return fil;
}

static __always_inline struct socket *bpf_sockfd_lookup(int fd)
{
    struct file *file;
    struct socket *sock;

    file = bpf_fget(fd);
    if (!file)
        return NULL;

    sock = _READ(file->private_data);
    return sock;
}

static __inline int32_t get_fd_from_conn_intf_core(struct go_interface conn_intf)
{
    void *fd_ptr;
    bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);

    int64_t sysfd;
    bpf_probe_read(&sysfd, sizeof(int64_t), fd_ptr + 16);
    return sysfd;
}

static __inline int32_t get_fd_from_conn_intf(struct go_interface conn_intf)
{
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
    return get_fd_from_conn_intf_core(conn_intf);
}

static __inline int32_t get_fd_from_http2_Framer(const void *framer_ptr)
{
    struct go_interface io_writer_interface;
    bpf_probe_read(&io_writer_interface, sizeof(io_writer_interface),
                   framer_ptr + 112);

    // At this point, we have the following struct:
    // go.itab.*google.golang.org/grpc/internal/transport.bufWriter,io.Writer
    // if (io_writer_interface.type != 1) {
    //   bpf_trace_printk("io_writer_interface.type ERROR \n");
    //   //return -1;
    // }

    struct go_interface conn_intf;
    bpf_probe_read(&conn_intf, sizeof(conn_intf),
                   io_writer_interface.ptr + 40);

    return get_fd_from_conn_intf(conn_intf);
}

// Copy the content of a hpack.HeaderField object into header_field_t object.
static void copy_header_field(struct header_field_t *dst, const void *header_field_ptr)
{
    struct gostring str = {};
    bpf_probe_read(&str, sizeof(str), header_field_ptr);
    if (str.len <= 0)
    {
        dst->size = 0;
        return;
    }
    dst->size = min(str.len, HEADER_FIELD_STR_SIZE);
    bpf_probe_read(dst->msg, dst->size, str.ptr);
}

static void copy_header_field_no_struct(char *dst, int *size, const void *header_field_ptr)
{
    struct gostring str = {};
    bpf_probe_read(&str, sizeof(str), header_field_ptr);
    if (str.len <= 0)
    {
        *size = 0;
        return;
    }
    *size = (int)min(str.len, HEADER_FIELD_STR_SIZE);
    // bpf_trace_printk("size: %d\n", *size);
    bpf_probe_read(dst, *size, str.ptr);
}

// Copies and submits content of an array of hpack.HeaderField to perf buffer.
// perf Buffer是CPU的缓冲区，每个CPU有自己的perf Buffer，ring Buffer是多个CPU共用的一个缓冲区，perf Buffer性能弱于ring Buffer
static void submit_headers(struct pt_regs *ctx, void *fields_ptr, int64_t fields_len, uint32_t stream_id)
{
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
    // bpf_trace_printk("tgid: %d\n", tgid);

    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("pid: %d\n", pid);

    // Size of the golang hpack.HeaderField struct.
    const size_t header_field_size = 40;

    struct grpc_event *event = get_header_event();
    if (event == NULL)
    {
        return;
    }

    event->trace_role = 2;
    event->pid = pid;
    event->tgid = tgid;
    event->stream_id = stream_id;
    event->timestamp_ns = bpf_ktime_get_ns();

    // bpf_trace_printk("(event): %d\n", event->pid);
    // bpf_trace_printk("(event): %d\n", event->tgid);
    // bpf_trace_printk("(event): %d\n", event->stream_id);
    // bpf_trace_printk("(event): %lldns\n", event->timestamp_ns);

    for (size_t i = 0; i < MAX_HEADER_COUNT; ++i)
    {
        if (i >= fields_len)
        {
            continue;
        }
        const void *header_field_ptr = fields_ptr + i * header_field_size;
        copy_header_field_no_struct(&event->name_msg, &event->name_size, header_field_ptr);
        copy_header_field_no_struct(&event->value_msg, &event->value_size, header_field_ptr + 16);

        // bpf_trace_printk("(event) name: %s\n", event->name_msg);
        // bpf_trace_printk("(event) name_size: %d\n", event->name_size);
        // bpf_trace_printk("(event) value: %s\n", event->value_msg);

        go_grpc_events.perf_submit(ctx, event, sizeof(*event));
    }
    // bpf_ktime_get_ns() 返回纳秒，1 ms = 1e6 ns
    // bpf_trace_printk("stream_id: %d, time: %lldns \n", stream_id, bpf_ktime_get_ns());
}

static void gostring_copy_header_field(char *dst, int *size, struct gostring *src)
{
    if (src->len <= 0)
    {
        *size = 0;
        return;
    }
    *size = (int)min(src->len, (int64_t)HEADER_FIELD_STR_SIZE);
    // bpf_trace_printk("size: %d\n", size);
    bpf_probe_read(dst, *size, src->ptr);
}
// --------------------------------------------- Assist Function End   ---------------------------------------------

// --------------------------------------------- Function Begin ---------------------------------------------
int probe_loopy_writer_write_header(struct pt_regs *ctx)
{
    const void *sp = (const void *)ctx->sp;

    // http2 通过stream实现多路复用，用一个唯一ID标识
    // client 创建的stream，ID为奇数，server创建的为偶数
    // stream ID 不可能被重复使用，如果一条连接上面 ID 分配完了，client 会新建一条连接
    uint32_t stream_id = 0;
    bpf_probe_read(&stream_id, sizeof(uint32_t), sp + 16);

    void *fields_ptr;
    const int kFieldsPtrOffset = 24;
    bpf_probe_read(&fields_ptr, sizeof(void *), sp + kFieldsPtrOffset);

    int64_t fields_len;
    const int kFieldsLenOffset = 8;
    bpf_probe_read(&fields_len, sizeof(int64_t), sp + kFieldsPtrOffset + kFieldsLenOffset);

    void *loopy_writer_ptr = NULL;
    bpf_probe_read(&loopy_writer_ptr, sizeof(loopy_writer_ptr), sp + 8);

    void *framer_ptr;
    bpf_probe_read(&framer_ptr, sizeof(framer_ptr), loopy_writer_ptr + 40);

    struct go_grpc_framer_t go_grpc_framer;
    bpf_probe_read(&go_grpc_framer, sizeof(go_grpc_framer), framer_ptr);

    const int32_t fd = get_fd_from_http2_Framer(go_grpc_framer.http2_framer);
    bpf_trace_printk("fd: %d\n", fd);
    if (fd == -1)
    {
        return 0;
    }

    submit_headers(ctx, fields_ptr, fields_len, stream_id);
    bpf_trace_printk("stream_id: %d\n", stream_id);

    bpf_trace_printk("----------> probe_loopy_writer_write_header done!\n");
    return 0;
}

int probe_http2_server_operate_headers(struct pt_regs *ctx)
{
    const void *sp = (const void *)ctx->sp;

    uint64_t *regs = go_regabi_regs(ctx);
    if (regs == NULL)
    {
        return 0;
    }

    void *http2_server_ptr = NULL;
    bpf_probe_read(&http2_server_ptr, sizeof(http2_server_ptr), sp + 8);

    void *frame_ptr;
    bpf_probe_read(&frame_ptr, sizeof(void *), sp + 16);

    struct go_interface conn_intf;
    bpf_probe_read(&conn_intf, sizeof(conn_intf), http2_server_ptr + 32);

    const int32_t fd = get_fd_from_conn_intf(conn_intf);
    if (fd == -1)
    {
        bpf_trace_printk("fd: -1\n");
        return 0;
    }
    bpf_trace_printk("fd: %d\n", fd);

    void *fields_ptr;
    bpf_probe_read(&fields_ptr, sizeof(void *), frame_ptr + 8);

    int64_t fields_len;
    bpf_probe_read(&fields_len, sizeof(int64_t), frame_ptr + 8 + 8);

    void *HeadersFrame_ptr;
    bpf_probe_read(&HeadersFrame_ptr, sizeof(HeadersFrame_ptr), frame_ptr + 0);

    void *FrameHeader_ptr = HeadersFrame_ptr + 0;

    uint32_t stream_id;
    bpf_probe_read(&stream_id, sizeof(uint32_t), FrameHeader_ptr + 8);

    bpf_trace_printk("stream_id: %d \n", stream_id);

    submit_headers(ctx, fields_ptr, fields_len, stream_id);
    bpf_trace_printk("----------> probe_http2_server_operate_headers done!\n");
    return 0;
}

int probe_hpack_header_encoder(struct pt_regs *ctx)
{

    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
    // bpf_trace_printk("tgid: %d\n", tgid);

    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("pid: %d\n", pid);

    const void *sp = (const void *)ctx->sp;

    void *encoder_ptr = NULL;
    bpf_probe_read(&encoder_ptr, sizeof(encoder_ptr), sp + 8);

    struct gostring name = {};
    bpf_probe_read(&name, sizeof(struct gostring), sp + 16);

    struct gostring value = {};
    bpf_probe_read(&value, sizeof(struct gostring), sp + 32);

    struct grpc_event *event = get_header_event();
    if (event == NULL)
    {
        return -1;
    }

    struct gostring *name_ptr = &name;
    struct gostring *value_ptr = &value;

    gostring_copy_header_field(&event->name_msg, &event->name_size, name_ptr);
    gostring_copy_header_field(&event->value_msg, &event->value_size, value_ptr);

    // bpf_trace_printk("name: %s\n", event->name_msg);
    // bpf_trace_printk("name_size: %d\n", event->name_size);
    // bpf_trace_printk("value: %s\n", event->value_msg);
    // bpf_trace_printk("value_size: %d\n", event->value_size);

    event->trace_role = 2;
    event->pid = pid;
    event->tgid = tgid;

    go_grpc_events.perf_submit(ctx, event, sizeof(*event));

    // bpf_trace_printk("----------> probe_hpack_header_encoder done!\n");
    return 0;
}

int probe_http2_framer_check_frame_order(struct pt_regs *ctx)
{

    const void *sp = (const void *)ctx->sp;

    struct go_interface frame_interface = {};
    bpf_probe_read(&frame_interface, sizeof(frame_interface), sp + 16);

    void *frame_header_ptr = frame_interface.ptr;
    uint8_t frame_type;
    bpf_probe_read(&frame_type, sizeof(uint8_t), frame_header_ptr + 1);

    // Consider only data frames (0)
    if (frame_type != 0)
        return 0;

    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
    // bpf_trace_printk("tgid: %d\n", tgid);

    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("pid: %d\n", pid);

    // All Frame types start with a frame header, so this is safe.
    // TODO(oazizi): Is there a more robust way based on DWARF info.
    // This would be required for dynamic tracing anyways.
    uint32_t stream_id;
    bpf_probe_read(&stream_id, sizeof(uint32_t), frame_header_ptr + 8);

    // ------------------------------------------------------
    // Extract members of DataFrame (data)
    // ------------------------------------------------------

    void *data_frame_ptr = frame_interface.ptr;

    char *data_ptr;
    bpf_probe_read(&data_ptr, sizeof(char *), data_frame_ptr + 16 + 0);

    int64_t data_len;
    bpf_probe_read(&data_len, sizeof(int64_t), data_frame_ptr + 16 + 8);

    // fd socket
    uint64_t *regs = go_regabi_regs(ctx);
    if (regs == NULL)
    {
        return 0;
    }

    void *framer_ptr = NULL;
    struct location_t http2_checkFrameOrder_fr_loc;
    http2_checkFrameOrder_fr_loc.type = kLocationTypeStack;
    http2_checkFrameOrder_fr_loc.offset = 8;
    assign_arg(&framer_ptr, sizeof(framer_ptr), http2_checkFrameOrder_fr_loc, sp, regs);

    int32_t fd = get_fd_from_http2_Framer(framer_ptr);

    struct socket *socket;
    socket = bpf_sockfd_lookup(fd);
    if (!socket)
    {
        bpf_trace_printk("Get socket error in server\n\n");
        return -1;
    }

    struct sock *sk;
    sk = _READ(socket->sk);
    if (!sk)
    {
        bpf_trace_printk("Read sock from socket error in server\n\n");
        return -1;
    }

    const struct inet_sock *inet = inet_sk(sk);
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;

    sport = _READ(inet->inet_sport);
    sport = ntohs(sport);
    dport = _READ(inet->inet_dport);
    dport = ntohs(dport);
    saddr = _READ(inet->inet_saddr);
    saddr = ntohl(saddr);
    daddr = _READ(inet->inet_daddr);
    daddr = ntohl(daddr);

    bpf_trace_printk("stream_id: %d\n", stream_id);
    // bpf_trace_printk("data_len: %d\n", data_len);
    bpf_trace_printk("fd (Frame): %d\n", fd);
    // bpf_trace_printk("sport: %u\n", sport);
    // bpf_trace_printk("dport: %u\n", dport);
    // bpf_trace_printk("saddr: %u\n", saddr);
    // bpf_trace_printk("daddr: %u\n", daddr);

    struct grpc_event *event = get_header_event();
    if (event == NULL)
    {
        return -1;
    }

    event->trace_role = 2;
    event->pid = pid;
    event->tgid = tgid;
    event->fd = fd;
    event->stream_id = stream_id;
    event->remote_ip = daddr;
    event->remote_port = dport;
    event->req_body_size = data_len;

    go_grpc_events.perf_submit(ctx, event, sizeof(*event));

    bpf_trace_printk("----------> probe_http2_framer_check_frame_order done!\n\n");
    return 0;
}

int probe_http2_framer_write_data(struct pt_regs *ctx)
{
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
    // bpf_trace_printk("tgid: %d\n", tgid);

    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("pid: %d\n", pid);

    const void *sp = (const void *)ctx->sp;

    uint32_t stream_id = 0;
    bpf_probe_read(&stream_id, sizeof(stream_id), sp + 16);

    int64_t data_len = 0;
    bpf_probe_read(&data_len, sizeof(data_len), sp + 32);

    bpf_trace_printk("stream_id: %d\n", stream_id);
    // bpf_trace_printk("data_len: %d\n", data_len);
    void *framer_ptr = NULL;
    bpf_probe_read(&framer_ptr, sizeof(framer_ptr), sp + 8);

    int32_t fd = get_fd_from_http2_Framer(framer_ptr);
    if (fd == -1)
    {
        bpf_trace_printk("fd: -1\n");
        return 0;
    }
    bpf_trace_printk("fd: %d\n", fd);

    struct grpc_event *event = get_header_event();
    if (event == NULL)
    {
        return -1;
    }

    event->trace_role = 2;
    event->pid = pid;
    event->tgid = tgid;
    event->stream_id = stream_id;
    event->fd = fd;
    event->reqsp_body_size = data_len;

    go_grpc_events.perf_submit(ctx, event, sizeof(*event));
    bpf_trace_printk("----------> probe_http2_framer_write_data done!\n");
    return 0;
}

// --------------------------------------------- Function End   ---------------------------------------------

/*

./ghz -c 10 -z 3m    --insecure    --proto ./greet.proto    --call greet.Greeter.SayHello    -d '{"name":"Joe"}'    172.19.238.118:50051
*/

/*
*/