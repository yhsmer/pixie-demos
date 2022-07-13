# -*- coding: UTF-8 -*-
from bcc import BPF

f = open("client_merge.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)

# (*loopyWriter).writeHeader() inside gRPC-go, which writes HTTP2 response headers
# Signature: func (l *loopyWriter) writeHeader(streamID uint32, endStream bool, hf []hpack.HeaderField, onWrite func())
# 服务端此函数接受明文header字段并将它们发送到内部缓冲区。函数签名和参数的类型定义是稳定的，自2018 年以来没有改变。
# 任务是读取第三个参数的内容hf，它是HeaderField. 我们使用dlv调试器计算出嵌套数据元素的偏移量，从堆栈中读取数据

bpf.attach_uprobe(name="./aliyun", sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader", fn_name="probe_loopy_writer_write_header")

# Probe for the golang.org/x/net/http2 library's header reader (client-side).
#
# Probes (*http2Client).operateHeaders(*http2.MetaHeadersFrame) inside gRPC-go, which processes
# HTTP2 headers of the received responses.
#
# Function signature:
#   func (t *http2Client) operateHeaders(frame *http2.MetaHeadersFrame)
#
# Symbol:
#   google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders
# 
# 跟踪在 gRPC 客户端收到的传入标头，operateHeaders 解析 Headers 帧

bpf.attach_uprobe(name="./aliyun", sym="google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders", fn_name="probe_http2_client_operate_headers")

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

bpf.attach_uprobe(name="./aliyun", sym="golang.org/x/net/http2/hpack.(*Encoder).WriteField", fn_name="probe_hpack_header_encoder")

# Verified to be stable from at least go1.6 to t go.1.13.
# func (fr *Framer) checkFrameOrder(f Frame) error
# Probes golang.org/x/net/http2.Framer for payload.
# As a proxy for the return probe on ReadFrame(), we currently probe checkFrameOrder, since return probes don't work for Go
# ReadFrame读取单个帧，主要检查帧的大小是否符合要求
# checkFrameOrder 主要是检查continuation帧是否收到，continuation帧用于在header帧过大进行分块时，借助continuation帧继续传输header信息
# retprobe 主要用于探测函数返回值，以及计算函数耗时
# read received data frame only

bpf.attach_uprobe(name="./aliyun", sym="golang.org/x/net/http2.(*Framer).checkFrameOrder", fn_name="probe_http2_framer_check_frame_order")

# Verified to be stable from go1.7 to t go.1.13.
# func (f *Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error
# 发送的数据包的data len + stream ID
# Probe for the golang.org/x/net/http2 library's frame writer
# WriteDataPadded writes a DATA frame with optional padding.

bpf.attach_uprobe(name="./aliyun", sym="golang.org/x/net/http2.(*Framer).WriteDataPadded", fn_name="probe_http2_framer_write_data")

bpf.trace_print()
# data req 12 resp 18