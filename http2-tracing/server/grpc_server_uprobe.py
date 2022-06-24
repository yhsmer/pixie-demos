# -*- coding: UTF-8 -*-
from bcc import BPF

f = open("server_bpf_uprobe.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)
# (*loopyWriter).writeHeader() inside gRPC-go, which writes HTTP2 headers to the server.
bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader", fn_name="probe_loopy_writer_write_header")

# Probe for the golang.org/x/net/http2 library's header reader (server-side)
bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders", fn_name="probe_http2_server_operate_headers")

# Probe for the hpack's header encoder.
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2/hpack.(*Encoder).WriteField", fn_name="probe_hpack_header_encoder")

# Probes golang.org/x/net/http2.Framer for payload.
# As a proxy for the return probe on ReadFrame(), we currently probe checkFrameOrder,
# since return probes don't work for Go
# write data
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).checkFrameOrder", fn_name="probe_http2_framer_check_frame_order")

# Probe for the golang.org/x/net/http2 library's frame writer
# WriteDataPadded writes a DATA frame with optional padding.
# bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).WriteDataPadded", fn_name="probe_http2_framer_write_data")

bpf.trace_print()