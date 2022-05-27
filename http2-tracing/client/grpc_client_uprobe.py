# -*- coding: UTF-8 -*-
from bcc import BPF

f = open("client_bpf_uprobe.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)
# bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader",
#                  fn_name="probe_loopy_writer_write_header")
bpf.attach_uprobe(name="./grpc_client", sym="google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders",
                  fn_name="probe_http2_client_operate_headers")
bpf.trace_print()
