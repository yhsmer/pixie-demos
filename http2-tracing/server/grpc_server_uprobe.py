# -*- coding: UTF-8 -*-
from bcc import BPF

f = open("server_bpf_uprobe.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)

# # (*loopyWriter).writeHeader() inside gRPC-go, which writes HTTP2 response headers
# bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader", fn_name="probe_loopy_writer_write_header")
# bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader", fn_name="test")

# # Probe for the golang.org/x/net/http2 library's request header reader (server-side)
# bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders", fn_name="probe_http2_server_operate_headers")

# Probe for the hpack's header encoder.
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2/hpack.(*Encoder).WriteField", fn_name="probe_hpack_header_encoder")

# Probes golang.org/x/net/http2.Framer for payload.
# As a proxy for the return probe on ReadFrame(), we currently probe checkFrameOrder,
# since return probes don't work for Go
# ReadFrame读取单个帧，主要检查帧的大小是否符合要求
# checkFrameOrder 主要是检查continuation帧是否收到，continuation帧用于在header帧过大进行分块时，借助continuation帧继续传输header信息
# retprobe 主要用于探测函数返回值，以及计算函数耗时
# read received data frame only
# bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).checkFrameOrder", fn_name="probe_http2_framer_check_frame_order")

'''
=>	frame.go:510	0x71511c*	488b8424d0000000	mov rax, qword ptr [rsp+0xd0]
	frame.go:510	0x715124	48890424		mov qword ptr [rsp], rax
	frame.go:510	0x715128	4889742408		mov qword ptr [rsp+0x8], rsi
	frame.go:510	0x71512d	4c89442410		mov qword ptr [rsp+0x10], r8
	frame.go:510	0x715132	e849030000		call $golang.org/x/net/http2.(*Framer).checkFrameOrder

=>	http2_server.go:639	0x746b0c*	48891424			mov qword ptr [rsp], rdx
	http2_server.go:639	0x746b10	488b8424a8000000		mov rax, qword ptr [rsp+0xa8]
	http2_server.go:639	0x746b18	4889442408			mov qword ptr [rsp+0x8], rax
	http2_server.go:639	0x746b1d	488b842420010000		mov rax, qword ptr [rsp+0x120]
	http2_server.go:639	0x746b25	4889442410			mov qword ptr [rsp+0x10], rax
	http2_server.go:639	0x746b2a	488b8c2428010000		mov rcx, qword ptr [rsp+0x128]
	http2_server.go:639	0x746b32	48894c2418			mov qword ptr [rsp+0x18], rcx
	http2_server.go:639	0x746b37	e824ccffff			call $google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders
'''

# padding
# Probe for the golang.org/x/net/http2 library's frame writer
# WriteDataPadded writes a DATA frame with optional padding.
# bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).WriteDataPadded", fn_name="probe_http2_framer_write_data")

bpf.trace_print()

# data req 12 resp 18