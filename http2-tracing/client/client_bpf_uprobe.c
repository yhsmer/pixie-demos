#include <uapi/linux/ptrace.h>
#define HEADER_FIELD_STR_SIZE 128
#define MAX_HEADER_COUNT 64
#define BPF_PROBE_READ_VAR(value, ptr) bpf_probe_read(&value, sizeof(value), ptr)

// We use the dlv debugger to figure out the offset of nested data

// 命令一个perf输出管道，用来代替bpf_trace_printk
// Creates a BPF table for pushing out custom event data to user space via a perf ring buffer
// This is the preferred method for pushing per-event data to user space.
// BPF_PERF_OUTPUT(go_http2_header_events);

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
  // bpf_trace_printk("copy_header_field done!\\n");
}

static __inline void my_copy_header_field(struct header_field_t* dst, struct gostring* src) {
  if (src->len <= 0) {
    dst->size = 0;
    return;
  }
  dst->size = min(src->len, (int64_t)HEADER_FIELD_STR_SIZE);
  bpf_probe_read(dst->msg, dst->size, src->ptr);
}

// Copies and submits content of an array of hpack.HeaderField to perf buffer.
// perf Buffer是CPU的缓冲区，每个CPU有自己的perf Buffer，ring Buffer是多个CPU共用的一个缓冲区，perf Buffer性能弱于ring Buffer
static void submit_headers(struct pt_regs* ctx, void* fields_ptr, int64_t fields_len) {
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
  // bpf_trace_printk("submit_headers done!\\n");
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

// Probe for the golang.org/x/net/http2 library's header reader (client-side).
//
// Probes (*http2Client).operateHeaders(*http2.MetaHeadersFrame) inside gRPC-go, which processes
// HTTP2 headers of the received responses.
//
// Function signature:
//   func (t *http2Client) operateHeaders(frame *http2.MetaHeadersFrame)
//
// Symbol:
//   google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders
// 
// 跟踪在 gRPC 客户端收到的传入标头，operateHeaders 解析 Headers 帧
int probe_http2_client_operate_headers(struct pt_regs* ctx) {
  const void* sp = (const void*)ctx->sp;

  void* frame_ptr;
  bpf_probe_read(&frame_ptr, sizeof(void*), sp + 16);

  void* HeadersFrame_ptr;
  BPF_PROBE_READ_VAR(HeadersFrame_ptr, frame_ptr + 0);

  void* fields_ptr;
  bpf_probe_read(&fields_ptr, sizeof(void*), frame_ptr + 8);

  int64_t fields_len;
  bpf_probe_read(&fields_len, sizeof(int64_t), frame_ptr + 8 + 8);

  void* FrameHeader_ptr = HeadersFrame_ptr + 0;

  uint8_t flags;
  bpf_probe_read(&flags, sizeof(uint8_t), FrameHeader_ptr + 2);
  // const bool end_stream = flags & kFlagHeadersEndStream;

  uint32_t stream_id;
  bpf_probe_read(&stream_id, sizeof(uint32_t), FrameHeader_ptr + 8);

  bpf_trace_printk("flags: %d\n", flags);
  bpf_trace_printk("end_stream: %d\n", flags & 0x1);
  bpf_trace_printk("stream_id: %d\n", stream_id);
  bpf_trace_printk("fields_len: %d\n", fields_len);

  /*
  const int kSizeOfHeaderField = 40;
  struct go_grpc_http2_header_event_t event = {};
  for (unsigned int i = 0; i < MAX_HEADER_COUNT; ++i) {
    if (i < fields_len) {
      // fill_header_field(event, fields_ptr + i * kSizeOfHeaderField, symaddrs);

      struct gostring name;
      BPF_PROBE_READ_VAR(name, fields_ptr + i * kSizeOfHeaderField + 0);

      struct gostring value;
      BPF_PROBE_READ_VAR(value, fields_ptr + i * kSizeOfHeaderField + 16);
      
      copy_header_field(&event.name, &name);
      copy_header_field(&event.value, &value);

      bpf_trace_printk("name: %s\\n", event.name.msg);
      bpf_trace_printk("value: %s\\n", event.value.msg);
      // go_grpc_events.perf_submit(ctx, event, sizeof(*event));
    }  
  }
  */
  submit_headers(ctx, fields_ptr, fields_len);
  // bpf_trace_printk("probe_http2_server_operate_headers done!\\n");
  return 0;
}