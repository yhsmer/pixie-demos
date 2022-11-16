# -*- coding: UTF-8 -*-
from bcc import BPF
from bcc.utils import printb

f = open("server_merge.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)

# (*loopyWriter).writeHeader() inside gRPC-go, which writes HTTP2 response headers
# Signature: func (l *loopyWriter) writeHeader(streamID uint32, endStream bool, hf []hpack.HeaderField, onWrite func())
# 服务端此函数接受明文header字段并将它们发送到内部缓冲区。函数签名和参数的类型定义是稳定的，自2018 年以来没有改变。
# 任务是读取第三个参数的内容hf，它是HeaderField. 我们使用dlv调试器计算出嵌套数据元素的偏移量，从堆栈中读取数据

bpf.attach_uprobe(
    name="./grpc_server",
    sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader",
    fn_name="probe_loopy_writer_write_header")

# 跟踪在 gRPC 服务端收到的传入标头，operateHeaders 解析 Headers 帧
# Probe for the golang.org/x/net/http2 library's header reader (server-side).
#
# Function signature:
#   func (t *http2Server) operateHeaders(frame *http2.MetaHeadersFrame, handle func(*Stream),
#                                        traceCtx func(context.Context, string) context.Context
#                                        (fatal bool)
# Symbol:
#   google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders

bpf.attach_uprobe(
    name="./grpc_server",
    sym=
    "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders",
    fn_name="probe_http2_server_operate_headers")

# Verified to be stable from at least go1.6 to t go.1.13.
# Probe for the hpack's header encoder.
#
# Function signature:
#   func (e *Encoder) WriteField(f HeaderField) error
#
#   WriteField encodes f into a single Write to e's underlying Writer.
#   This function may also produce bytes for "Header Table Size Update" if necessary.
#   If produced, it is done before encoding f.
#   每次只处理header部分的一对key/value
#
# Symbol:
#   golang.org/x/net/http2/hpack.(*Encoder).WriteField

# bpf.attach_uprobe(name="./grpc_server",
#                   sym="golang.org/x/net/http2/hpack.(*Encoder).WriteField",
#                   fn_name="probe_hpack_header_encoder")

# Verified to be stable from at least go1.6 to t go.1.13.
# func (fr *Framer) checkFrameOrder(f Frame) error
# Probes golang.org/x/net/http2.Framer for payload.
# As a proxy for the return probe on ReadFrame(), we currently probe checkFrameOrder, since return probes don't work for Go
# ReadFrame读取单个帧，主要检查帧的大小是否符合要求
# checkFrameOrder 主要是检查continuation帧是否收到，continuation帧用于在header帧过大进行分块时，借助continuation帧继续传输header信息
# retprobe 主要用于探测函数返回值，以及计算函数耗时
# read received data frame only

bpf.attach_uprobe(name="./grpc_server",
                  sym="golang.org/x/net/http2.(*Framer).checkFrameOrder",
                  fn_name="probe_http2_framer_check_frame_order")

# Verified to be stable from go1.7 to t go.1.13.
# func (f *Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error
# 发送的数据包的data len + stream ID
# Probe for the golang.org/x/net/http2 library's frame writer
# WriteDataPadded writes a DATA frame with optional padding.

bpf.attach_uprobe(name="./grpc_server",
                  sym="golang.org/x/net/http2.(*Framer).WriteDataPadded",
                  fn_name="probe_http2_framer_write_data")

output = 1
if output:
    bpf.trace_print()
else:
    print("%-20s %s" % ("[key]", "[value]"))

    def print_event(cpu, data, size):
        event = bpf["go_grpc_events"].event(data)

        printb(b"%-20s %d" % (b"trace_role", event.trace_role))
        printb(b"%-20s %d" % (b"pid", event.pid))
        printb(b"%-20s %d" % (b"tgid", event.tgid))

        if event.fd != 0:
            printb(b"%-20s %d" % (b"fd", event.fd))

        if event.stream_id != 0:
            printb(b"%-20s %d" % (b"stream_id", event.stream_id))

        if event.remote_ip != 0:
            printb(b"%-20s %d" % (b"remote_ip", event.remote_ip))

        if event.remote_port != 0:
            printb(b"%-20s %d" % (b"remote_port", event.remote_port))

        if len(event.content_type) != 0:
            printb(b"%-20s %s" % (b"content_type", event.content_type))

        if len(event.req_method) != 0:
            printb(b"%-20s %s" % (b"req_method", event.req_method))

        if len(event.req_path) != 0:
            printb(b"%-20s %s" % (b"req_path", event.req_path))

        if len(event.req_status) != 0:
            printb(b"%-20s %s" % (b"req_status", event.req_status))

        if event.req_body_size != 0:
            printb(b"%-20s %d" % (b"req_body_size", event.req_body_size))

        if event.reqsp_body_size != 0:
            printb(b"%-20s %d" % (b"reqsp_body_size", event.reqsp_body_size))

        if event.timestamp_ns != 0:
            printb(b"%-20s %d(ns)" % (b"timestamp_ns", event.timestamp_ns))

        if event.name_size != 0 and event.value_size != 0:
            printb(b"%-20s %s" % (event.name_msg[:event.name_size],
                                  event.value_msg[:event.value_size]))

        print('')

    # loop with callback to print_event
    bpf["go_grpc_events"].open_perf_buffer(print_event)
    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
# data req 12 resp 18