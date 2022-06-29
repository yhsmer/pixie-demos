# -*- coding: UTF-8 -*-
from bcc import BPF

f = open("server_bpf_uprobe.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)

bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc.(*serverStream).SendMsg", fn_name="hello_SendMsg")
bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc.(*serverStream).RecvMsg", fn_name="hello_RecvMsg")

# (*loopyWriter).writeHeader() inside gRPC-go, which writes HTTP2 response headers
bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader", fn_name="probe_loopy_writer_write_header")

# Probe for the golang.org/x/net/http2 library's request header reader (server-side)
bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders", fn_name="probe_http2_server_operate_headers")

# Probe for the hpack's header encoder.
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2/hpack.(*Encoder).WriteField", fn_name="probe_hpack_header_encoder")

# Probes golang.org/x/net/http2.Framer for payload.
# As a proxy for the return probe on ReadFrame(), we currently probe checkFrameOrder,
# since return probes don't work for Go
# ReadFrame读取单个帧，主要检查帧的大小是否符合要求
# checkFrameOrder 主要是检查continuation帧是否收到，continuation帧用于在header帧过大进行分块时，借助continuation帧继续传输header信息
# retprobe 主要用于探测函数返回值，以及计算函数耗时
# read received data frame only
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).checkFrameOrder", fn_name="probe_http2_framer_check_frame_order")

# # Probe for the golang.org/x/net/http2 library's frame writer
# # WriteDataPadded writes a DATA frame with optional padding.
# bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).WriteDataPadded", fn_name="probe_http2_framer_write_data")

bpf.trace_print()