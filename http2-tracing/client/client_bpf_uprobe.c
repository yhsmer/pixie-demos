#include <uapi/linux/ptrace.h>
#define HEADER_FIELD_STR_SIZE 128
#define MAX_HEADER_COUNT 64
#define MAX_DATA_SIZE 16384
#define BPF_PROBE_READ_VAR(value, ptr) bpf_probe_read(&value, sizeof(value), ptr)
BPF_PERF_OUTPUT(go_http2_header_events);

struct go_interface {
  int64_t type;
  void* ptr;
};

struct data_t{
  int int_value;
  char name[20];
  char char_value[HEADER_FIELD_STR_SIZE];
};


struct header_field_t {
  int32_t size;
  char msg[HEADER_FIELD_STR_SIZE];
};

struct go_grpc_data_event_t {
  //char data[MAX_DATA_SIZE];
  char data[128];
};

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
// name, type, size
BPF_PERCPU_ARRAY(data_event_buffer_heap, struct go_grpc_data_event_t, 1);
static __inline struct go_grpc_data_event_t* get_data_event() {
  uint32_t kZero = 0;
  return data_event_buffer_heap.lookup(&kZero);
}

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
// C语言没有引用传递，只有值传递，或者传指针
static void submit_data_t(struct pt_regs* ctx, char *name, int int_value, char *char_value){
  struct data_t data = {};
  //strcpy(data.name, name);
  //data.int_value = int_value;
  //strcpy(data.char_value, char_value);
  go_http2_header_events.perf_submit(ctx, &data, sizeof(data));
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

    submit_data_t(ctx, event.name.msg, -1234, event.value.msg);
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

  uint32_t stream_id;
  bpf_probe_read(&stream_id, sizeof(uint32_t), FrameHeader_ptr + 8);

  bpf_trace_printk("flags: %d\n", flags);
  bpf_trace_printk("end_stream: %d\n", flags & 0x1);
  bpf_trace_printk("stream_id: %d\n", stream_id);
  bpf_trace_printk("fields_len: %d\n", fields_len);

  //submit_data_t(ctx, "flags", flags, "");
  //submit_data_t(ctx, "end_stream", flags & 0x1, "");
  //submit_data_t(ctx, "stream_id", stream_id, "");
  //submit_data_t(ctx, "fields_len", fields_len, "");
  submit_headers(ctx, fields_ptr, fields_len);
  bpf_trace_printk("----------> probe_http2_client_operate_headers done!\n");
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

  //submit_data_t(ctx, event.name.msg, -1234, event.value.msg);

  bpf_trace_printk("----------> probe_hpack_header_encoder done!\n");
  return 0;
}


// Probes golang.org/x/net/http2.Framer for payload.
//
// payload就是data的有效数据部分，在http2帧的通用格式中，payload用来表示每种类型帧的有效数据部分
// Package http2 implements the HTTP/2 protocol.
// 
// As a proxy for the return probe on ReadFrame(), we currently probe checkFrameOrder,
// since return probes don't work for Go.
// 
// Frame 是 HTTP/2 里面最小的数据传输单位
// 
// Function signature:
//   func (fr *Framer) checkFrameOrder(f Frame) error
//
// Symbol:
//   golang.org/x/net/http2.(*Framer).checkFrameOrder
//
// Verified to be stable from at least go1.6 to t go.1.13.
// Data帧的data部分未解析出来
int probe_http2_framer_check_frame_order(struct pt_regs* ctx) {
  // ---------------------------------------------
  // Extract arguments
  // ---------------------------------------------

  const void* sp = (const void*)ctx->sp;

  void* framer_ptr = NULL;
  bpf_probe_read(&framer_ptr, sizeof(framer_ptr), sp + 8);

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

  //submit_data_t(ctx, "flags", flags, "");
  //submit_data_t(ctx, "end_stream", end_stream, "");
  //submit_data_t(ctx, "stream_id", stream_id, "");
  //submit_data_t(ctx, "frame_type", frame_type, "");

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

  bpf_trace_printk("data_len: %d\n", data_len);

  // ------------------------------------------------------
  // Submit
  // ------------------------------------------------------
  
  //struct go_grpc_data_event_t* info = get_data_event();
  struct go_grpc_data_event_t info = {};
  // struct go_grpc_data_event_t info = {};

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
    struct go_grpc_http2_header_event_t event = {};
    //bpf_probe_read(event.name.msg, data_buf_size, data_ptr);
    bpf_probe_read(info.data, 18, data_ptr);
    bpf_trace_printk("data: %s\n", info.data); 
    //bpf_trace_printk("data: %s\n", event.name.msg);
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
