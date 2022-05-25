#include <uapi/linux/ptrace.h>

#define HEADER_FIELD_STR_SIZE 128
#define MAX_HEADER_COUNT 64

// We use the dlv debugger to figure out the offset of nested data

// 命令一个perf输出管道，用来代替bpf_trace_printk
// Creates a BPF table for pushing out custom event data to user space via a perf ring buffer
// This is the preferred method for pushing per-event data to user space.
BPF_PERF_OUTPUT(go_http2_header_events);

struct header_field_t {
  int32_t size;
  char msg[HEADER_FIELD_STR_SIZE];
};

struct go_grpc_http2_header_event_t {
  struct header_field_t name;
  struct header_field_t value;
};

// This matches the golang string object memory layout. Used to help read golang string objects in BPF code.
struct gostring {
  const char* ptr;
  int64_t len;
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
}

// Copies and submits content of an array of hpack.HeaderField to perf buffer.
// perf Buffer是CPU的缓冲区，每个CPU有自己的perf Buffer，ring Buffer是多个CPU共用的一个缓冲区，perf Buffer性能弱于ring Buffer
// static 函数表示对其他文件隐藏，作用域局限于本文件
static void submit_headers(struct pt_regs* ctx, void* fields_ptr, int64_t fields_len) {
  // Size of the golang hpack.HeaderField struct.
  const size_t header_field_size = 40;
  struct go_grpc_http2_header_event_t event = {};
  for (size_t i = 0; i < MAX_HEADER_COUNT; ++i) {
    if (i >= fields_len) {
      continue;
    }
    const void* header_field_ptr = fields_ptr + i * header_field_size;
    copy_header_field(&event.name, header_field_ptr);
    copy_header_field(&event.value, header_field_ptr + 16);
    // 将数据输出到perf Buffer
    go_http2_header_events.perf_submit(ctx, &event, sizeof(event));
  }
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
  const void* sp = (const void*)ctx->sp;
  
  uint32_t stream_id = 0;
  bpf_probe_read(&stream_id, sizeof(uint32_t), sp + 16);
  // assign_arg(&stream_id, sizeof(stream_id), symaddrs->writeHeader_streamID_loc, sp, regs);

  bool end_stream = false;
  bpf_probe_read(&end_stream, sizeof(end_stream), sp + 20);
  // assign_arg(&end_stream, sizeof(end_stream), symaddrs->writeHeader_endStream_loc, sp, regs);

  void* fields_ptr;
	const int kFieldsPtrOffset = 24;
  bpf_probe_read(&fields_ptr, sizeof(void*), sp + kFieldsPtrOffset);

  int64_t fields_len;
	const int kFieldsLenOffset = 8;
  bpf_probe_read(&fields_len, sizeof(int64_t), sp + kFieldsPtrOffset + kFieldsLenOffset);

  submit_headers(ctx, fields_ptr, fields_len);
  return 0;
}

// Signature: func (t *http2Server) operateHeaders(frame *http2.MetaHeadersFrame, handle func(*Stream),
// traceCtx func(context.Context, string) context.Context)
// 跟踪在 gRPC 服务端收到的传入标头，operateHeaders 解析 Headers 帧
int probe_http2_server_operate_headers(struct pt_regs* ctx) {
  const void* sp = (const void*)ctx->sp;

  void* frame_ptr;
  bpf_probe_read(&frame_ptr, sizeof(void*), sp + 16);

  void* fields_ptr;
  bpf_probe_read(&fields_ptr, sizeof(void*), frame_ptr + 8);

  int64_t fields_len;
  bpf_probe_read(&fields_len, sizeof(int64_t), frame_ptr + 8 + 8);

  submit_headers(ctx, fields_ptr, fields_len);
  return 0;
}