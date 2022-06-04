# -*- coding: UTF-8 -*-
from bcc import BPF

f = open("server_bpf_uprobe.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader", fn_name="probe_loopy_writer_write_header")
bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders", fn_name="probe_http2_server_operate_headers")
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2/hpack.(*Encoder).WriteField", fn_name="probe_hpack_header_encoder")
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).checkFrameOrder", fn_name="probe_http2_framer_check_frame_order")
# bpf.trace_print()