#include <uapi/linux/ptrace.h>
#define HEADER_FIELD_STR_SIZE 128
#define MAX_HEADER_COUNT 64
#define MAX_DATA_SIZE 16384
const int32_t kInvalidFD = -1;
// We use the dlv debugger to figure out the offset of nested data

// 命令一个perf输出管道，用来代替bpf_trace_printk
// Creates a BPF table for pushing out custom event data to user space via a perf ring buffer
// This is the preferred method for pushing per-event data to user space.
// BPF_PERF_OUTPUT(go_http2_header_events);

struct header_field_t {
  int32_t size;
  char msg[HEADER_FIELD_STR_SIZE];
};

// TODO(oazizi): Remove this struct; Use DWARF instead.
struct go_grpc_framer_t {
  void* writer;
  void* http2_framer;
};

struct go_grpc_http2_header_event_t {
  struct header_field_t name;
  struct header_field_t value;
};

struct go_grpc_data_event_t {
  //char data[MAX_DATA_SIZE];
  char data[128];
};

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
BPF_PERCPU_ARRAY(data_event_buffer_heap, struct go_grpc_data_event_t, 1);
static __inline struct go_grpc_data_event_t* get_data_event() {
  uint32_t kZero = 0;
  return data_event_buffer_heap.lookup(&kZero);
}

// This matches the golang string object memory layout. Used to help read golang string objects in BPF code.
struct gostring {
  const char* ptr;
  int64_t len;
};

struct go_interface {
  int64_t type;
  void* ptr;
};

static int64_t min(int64_t l, int64_t r) {
  return l < r ? l : r;
}

// Copy the content of a hpack.HeaderField object into header_field_t object.
static void copy_header_field(struct header_field_t* dst, const void* header_field_ptr) {
  struct gostring str = {};
  bpf_probe_read(&str, sizeof(str), header_field_ptr);
  if (str.len <= 0) {
    dst->size = 0;
    return;
  }
  dst->size = min(str.len, HEADER_FIELD_STR_SIZE);
  bpf_probe_read(dst->msg, dst->size, str.ptr);
  // bpf_trace_printk("copy_header_field done!\\n");
}

static void gostring_copy_header_field(struct header_field_t* dst, struct gostring* src) {
  if (src->len <= 0) {
    dst->size = 0;
    return;
  }
  dst->size = min(src->len, (int64_t)HEADER_FIELD_STR_SIZE);
  bpf_probe_read(dst->msg, dst->size, src->ptr);
}

// Copies and submits content of an array of hpack.HeaderField to perf buffer.
// perf Buffer是CPU的缓冲区，每个CPU有自己的perf Buffer，ring Buffer是多个CPU共用的一个缓冲区，perf Buffer性能弱于ring Buffer
static void submit_headers(struct pt_regs* ctx, void* fields_ptr, int64_t fields_len, uint32_t stream_id) {
  // Size of the golang hpack.HeaderField struct.
  const size_t header_field_size = 40;
  // struct go_grpc_http2_header_event_t event = {};
  for (size_t i = 0; i < MAX_HEADER_COUNT; ++i) {
    if (i >= fields_len) {
      continue;
    }
    struct go_grpc_http2_header_event_t event = {};
    const void* header_field_ptr = fields_ptr + i * header_field_size;
    copy_header_field(&event.name, header_field_ptr);
    copy_header_field(&event.value, header_field_ptr + 16);

    // bpf_trace_printk("[name='%s' value='%s']\\n", event.name.msg, event.value.msg);
    bpf_trace_printk("name: %s\n", event.name.msg);
    bpf_trace_printk("value: %s\n", event.value.msg);
    
    // 将数据输出到perf Buffer
    // go_http2_header_events.perf_submit(ctx, &event, sizeof(event));
  }
  // bpf_ktime_get_ns() 返回纳秒，1 ms = 1e6 ns
  bpf_trace_printk("stream_id: %d, time: %lldns \n", stream_id ,bpf_ktime_get_ns());
  // bpf_trace_printk("submit_headers done!\\n");
}

static __inline int32_t get_fd_from_conn_intf_core(struct go_interface conn_intf) {
  // REQUIRE_SYMADDR(symaddrs->FD_Sysfd_offset, kInvalidFD);

  // if (conn_intf.type == symaddrs->internal_syscallConn) {
  //   REQUIRE_SYMADDR(symaddrs->syscallConn_conn_offset, kInvalidFD);
  //   const int kSyscallConnConnOffset = 0;
  //   bpf_probe_read(&conn_intf, sizeof(conn_intf),
  //                  conn_intf.ptr + symaddrs->syscallConn_conn_offset);
  // }

  // if (conn_intf.type == symaddrs->tls_Conn) {
  //   REQUIRE_SYMADDR(symaddrs->tlsConn_conn_offset, kInvalidFD);
  //   bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_intf.ptr + symaddrs->tlsConn_conn_offset);
  // }

  // if (conn_intf.type != symaddrs->net_TCPConn) {
  //   return kInvalidFD;
  // }

  bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_intf.ptr + 0);

  void* fd_ptr;
  bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);

  int64_t sysfd;
  bpf_probe_read(&sysfd, sizeof(int64_t), fd_ptr + 16);

  return sysfd;
}

static __inline int32_t get_fd_from_conn_intf(struct go_interface conn_intf) {
  return get_fd_from_conn_intf_core(conn_intf);
}

static __inline int32_t get_fd_from_http2_Framer(const void* framer_ptr) {
  
  // struct go_interface io_writer_interface;
  // bpf_probe_read(io_writer_interface, sizeof(io_writer_interface), framer_ptr + 112);

  // At this point, we have the following struct:
  // go.itab.*google.golang.org/grpc/internal/transport.bufWriter,io.Writer

  // if (io_writer_interface.type != symaddrs->transport_bufWriter) {
  //   return kInvalidFD;
  // }

  struct go_interface conn_intf;
  // bpf_probe_read(conn_intf, sizeof(conn_intf), io_writer_interface.ptr + 40);

  return get_fd_from_conn_intf(conn_intf);
}

/*
type HeaderField struct {
  // 16 16
	Name, Value string

	// Sensitive means that this header field should never be
	// indexed.
	Sensitive bool
}
*/
// 4 1 
// Signature: func (l *loopyWriter) writeHeader(streamID uint32, endStream bool, hf []hpack.HeaderField, onWrite func())
// 服务端此函数接受明文header字段并将它们发送到内部缓冲区。函数签名和参数的类型定义是稳定的，自2018 年以来没有改变。
// 任务是读取第三个参数的内容hf，它是HeaderField. 我们使用dlv调试器计算出嵌套数据元素的偏移量，从堆栈中读取数据
int probe_loopy_writer_write_header(struct pt_regs* ctx) {
  
  uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_trace_printk("tgid: %d\n", tgid);

  u32 pid = bpf_get_current_pid_tgid();
  bpf_trace_printk("pid: %d\n", pid);

  const void* sp = (const void*)ctx->sp;
  
  // http2 通过stream实现多路复用，用一个唯一ID标识
  // client 创建的stream，ID为奇数，server创建的为偶数 
  // stream ID 不可能被重复使用，如果一条连接上面 ID 分配完了，client 会新建一条连接
  uint32_t stream_id = 0;
  bpf_probe_read(&stream_id, sizeof(uint32_t), sp + 16);

  // end stream 表示该stream不会再发送任何数据了
  bool end_stream = false;
  bpf_probe_read(&end_stream, sizeof(end_stream), sp + 20);

  void* fields_ptr;
	const int kFieldsPtrOffset = 24;
  bpf_probe_read(&fields_ptr, sizeof(void*), sp + kFieldsPtrOffset);

  int64_t fields_len;
	const int kFieldsLenOffset = 8;
  bpf_probe_read(&fields_len, sizeof(int64_t), sp + kFieldsPtrOffset + kFieldsLenOffset);

  void* loopy_writer_ptr = NULL;
  bpf_probe_read(&loopy_writer_ptr, sizeof(loopy_writer_ptr), sp + 8);
  
  void* framer_ptr;
  // bpf_probe_read(&value, sizeof(value), ptr)的宏定义
  bpf_probe_read(&framer_ptr, sizeof(framer_ptr), loopy_writer_ptr + 40);

  struct go_grpc_framer_t go_grpc_framer;
  bpf_probe_read(&go_grpc_framer, sizeof(go_grpc_framer), framer_ptr);

  // const int32_t fd = get_fd_from_http2_Framer(go_grpc_framer.http2_framer);
  // bpf_trace_printk("fd: %d", fd);
  // if (fd == kInvalidFD) {
  //   return 0;
  // }

  submit_headers(ctx, fields_ptr, fields_len, stream_id);
  bpf_trace_printk("stream_id: %d\n", stream_id);
  bpf_trace_printk("end_stream: %d\n", end_stream);

  bpf_trace_printk("----------> probe_loopy_writer_write_header done!\n");
  return 0;
}

// Signature: func (t *http2Server) operateHeaders(frame *http2.MetaHeadersFrame, handle func(*Stream),
// traceCtx func(context.Context, string) context.Context)
// 跟踪在 gRPC 服务端收到的传入标头，operateHeaders 解析 Headers 帧
int probe_http2_server_operate_headers(struct pt_regs* ctx) {
  uint32_t tgid = bpf_get_current_pid_tgid() >> 32;
  bpf_trace_printk("tgid: %d\n", tgid);

  u32 pid = bpf_get_current_pid_tgid();
  bpf_trace_printk("pid: %d\n", pid);

  const void* sp = (const void*)ctx->sp;

  void* frame_ptr;
  bpf_probe_read(&frame_ptr, sizeof(void*), sp + 16);

  void* fields_ptr;
  bpf_probe_read(&fields_ptr, sizeof(void*), frame_ptr + 8);

  int64_t fields_len;
  bpf_probe_read(&fields_len, sizeof(int64_t), frame_ptr + 8 + 8);

  void* http2_server_ptr = NULL;
  bpf_probe_read(&http2_server_ptr, sizeof(http2_server_ptr), sp + 8);

  void* HeadersFrame_ptr;
  bpf_probe_read(&HeadersFrame_ptr, sizeof(HeadersFrame_ptr), frame_ptr + 0);

  void* FrameHeader_ptr = HeadersFrame_ptr + 0;

  uint32_t stream_id;
  bpf_probe_read(&stream_id, sizeof(uint32_t), FrameHeader_ptr + 8);

  // ---------------------------------------------
  // Extract members
  // ---------------------------------------------

  struct go_interface conn_intf;
  // offset 16 or 24
  bpf_probe_read(&conn_intf, sizeof(conn_intf), http2_server_ptr + 24);

  const int32_t fd = get_fd_from_conn_intf(conn_intf);
  bpf_trace_printk("fd: %d\n", fd);

  submit_headers(ctx, fields_ptr, fields_len, stream_id);
  bpf_trace_printk("----------> probe_http2_server_operate_headers done!\n");
  return 0;
}

// Probe for the hpack's header encoder.
//
// Function signature:
//   func (e *Encoder) WriteField(f HeaderField) error
// 
//   WriteField encodes f into a single Write to e's underlying Writer. 
//   This function may also produce bytes for "Header Table Size Update" if necessary.
//   If produced, it is done before encoding f.
//   每次只处理header部分的一对key/value
// 
// Symbol:
//   golang.org/x/net/http2/hpack.(*Encoder).WriteField
//
// Verified to be stable from at least go1.6 to t go.1.13.
int probe_hpack_header_encoder(struct pt_regs* ctx) {
  // ---------------------------------------------
  // Extract arguments (on stack)
  // ---------------------------------------------

  const void* sp = (const void*)ctx->sp;

  void* encoder_ptr = NULL;
  bpf_probe_read(&encoder_ptr, sizeof(encoder_ptr), sp + 8);

  struct gostring name = {};
  bpf_probe_read(&name, sizeof(struct gostring), sp + 16);

  struct gostring value = {};
  bpf_probe_read(&value, sizeof(struct gostring), sp + 32);

  // ------------------------------------------------------
  // Process
  // ------------------------------------------------------
  struct go_grpc_http2_header_event_t event = {};
  struct gostring* name_ptr = &name;
  struct gostring* value_ptr = &value;
  gostring_copy_header_field(&event.name, name_ptr);
  gostring_copy_header_field(&event.value, value_ptr);

  bpf_trace_printk("name: %s\n", event.name.msg);
  bpf_trace_printk("value: %s\n", event.value.msg);  

  bpf_trace_printk("----------> probe_hpack_header_encoder done!\n");
  return 0;
}

// Probes golang.org/x/net/http2.Framer for payload.
//
// As a proxy for the return probe on ReadFrame(), we currently probe checkFrameOrder,
// since return probes don't work for Go.
//
// Function signature:
//   func (fr *Framer) checkFrameOrder(f Frame) error
//
// Symbol:
//   golang.org/x/net/http2.(*Framer).checkFrameOrder
//
// Verified to be stable from at least go1.6 to t go.1.13.
int probe_http2_framer_check_frame_order(struct pt_regs* ctx) {
  // ---------------------------------------------
  // Extract arguments
  // ---------------------------------------------

  const void* sp = (const void*)ctx->sp;

  void* framer_ptr = NULL;
  bpf_probe_read(&framer_ptr, sizeof(framer_ptr), sp + 8);

  // int32_t fd = get_fd_from_http2_Framer(framer_ptr);
  // if (fd == -1) {
  //   return 0;
  // }

  struct go_interface frame_interface = {};
  bpf_probe_read(&frame_interface, sizeof(frame_interface), sp + 16);

  // ------------------------------------------------------
  // Extract members of Framer (fd)
  // ------------------------------------------------------

  /*

  */

  // ------------------------------------------------------
  // Extract members of FrameHeader (type, flags, stream_id)
  // ------------------------------------------------------

  // All Frame types start with a frame header, so this is safe.
  // TODO(oazizi): Is there a more robust way based on DWARF info.
  // This would be required for dynamic tracing anyways.
  void* frame_header_ptr = frame_interface.ptr;

  uint8_t frame_type;
  bpf_probe_read(&frame_type, sizeof(uint8_t), frame_header_ptr + 1);

  uint8_t flags;
  bpf_probe_read(&flags, sizeof(uint8_t), frame_header_ptr + 2);
  const bool end_stream = flags & 0x1;

  uint32_t stream_id;
  bpf_probe_read(&stream_id, sizeof(uint32_t), frame_header_ptr + 8);

  bpf_trace_printk("frame_type: %d\n", frame_type);
  bpf_trace_printk("flags: %d\n", flags);
  bpf_trace_printk("end_stream: %d\n", end_stream);
  bpf_trace_printk("stream_id: %d\n", stream_id);

  // Consider only data frames (0).
  if (frame_type != 0) {
    bpf_trace_printk("frame_type: %d, != 0, is not a data frames. returned! \n\n", frame_type);
    return 0;
  }

  // ------------------------------------------------------
  // Extract members of DataFrame (data)
  // ------------------------------------------------------

  // Reinterpret as data frame.
  void* data_frame_ptr = frame_interface.ptr;

  char* data_ptr;
  bpf_probe_read(&data_ptr, sizeof(char*), data_frame_ptr + 16 + 0);

  int64_t data_len;
  bpf_probe_read(&data_len, sizeof(int64_t), data_frame_ptr + 16 + 8);

  bpf_trace_printk("------------> (Data Frame) frame_type: %d\n", frame_type);
  bpf_trace_printk("data_len: %d\n", data_len);

  // ------------------------------------------------------
  // Submit
  // ------------------------------------------------------

  // struct go_grpc_data_event_t* info = get_data_event();
  struct go_grpc_data_event_t info = {};

  uint32_t data_buf_size = min(data_len, MAX_DATA_SIZE);
  

  // Note that we have some black magic below with the string sizes.
  // This is to avoid passing a size of 0 to bpf_probe_read(),
  // which causes BPF verifier issues on kernel 4.14.
  // The black magic includes an asm volatile, because otherwise Clang
  // will optimize our magic away.
  size_t data_buf_size_minus_1 = data_buf_size - 1;
  asm volatile("" : "+r"(data_buf_size_minus_1) :);
  data_buf_size = data_buf_size_minus_1 + 1;

  bpf_trace_printk("data_buf_size: %d\n", data_buf_size);
  if (data_buf_size_minus_1 < MAX_DATA_SIZE) {
    bpf_probe_read(info.data, 12, data_ptr);
    bpf_trace_printk("data: %s\n", info.data); 
  }

  bpf_trace_printk("----------> probe_http2_framer_check_frame_order done!\n");
  return 0;
}

// Probe for the golang.org/x/net/http2 library's frame writer.
//
// Function signature:
//   func (f *Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error
//
// Symbol:
//   golang.org/x/net/http2.(*Framer).WriteDataPadded
//
// Verified to be stable from go1.7 to t go.1.13.
int probe_http2_framer_write_data(struct pt_regs* ctx) {
  // ---------------------------------------------
  // Extract arguments
  // ---------------------------------------------

  const void* sp = (const void*)ctx->sp;

  void* framer_ptr = NULL;
  bpf_probe_read(&framer_ptr, sizeof(framer_ptr), sp + 8);

  uint32_t stream_id = 0;
  bpf_probe_read(&stream_id, sizeof(stream_id), sp + 16);

  bool end_stream = 0;
  bpf_probe_read(&end_stream, sizeof(end_stream), sp + 20);

  bpf_trace_printk("end_stream: %d\n", end_stream);
  bpf_trace_printk("stream_id: %d\n", stream_id);

  char* data_ptr = NULL;
  bpf_probe_read(&data_ptr, sizeof(data_ptr), sp + 24);

  int64_t data_len = 0;
  bpf_probe_read(&data_len, sizeof(data_len), sp + 32);

  struct go_grpc_data_event_t info = {};

  uint32_t data_buf_size = min(data_len, MAX_DATA_SIZE);

  // Note that we have some black magic below with the string sizes.
  // This is to avoid passing a size of 0 to bpf_probe_read(),
  // which causes BPF verifier issues on kernel 4.14.
  // The black magic includes an asm volatile, because otherwise Clang
  // will optimize our magic away.
  size_t data_buf_size_minus_1 = data_buf_size - 1;
  asm volatile("" : "+r"(data_buf_size_minus_1) :);
  data_buf_size = data_buf_size_minus_1 + 1;

  bpf_trace_printk("data_buf_size: %d\n", data_buf_size);
  if (data_buf_size_minus_1 < MAX_DATA_SIZE) {
    bpf_probe_read(info.data, sizeof(info.data), data_ptr);
    bpf_trace_printk("data: %s\n", info.data); 
  }

  bpf_trace_printk("----------> probe_http2_framer_write_data done!\n");
  return 0;
}

void hello_SendMsg(struct pt_regs* ctx) {
  bpf_trace_printk("================ hello_SendMsg\n");
}

void hello_RecvMsg(struct pt_regs* ctx) {
  bpf_trace_printk("================ hello_RecvMsg\n");
}