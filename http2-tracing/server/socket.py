# -*- coding: UTF-8 -*-
from bcc import BPF

f = open("socket.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)

# Probe for the golang.org/x/net/http2 library's request header reader (server-side)
#bpf.attach_uprobe(name="./grpc_server", sym="google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders", fn_name="probe_http2_server_operate_headers")
bpf.attach_uprobe(name="./grpc_server", sym="golang.org/x/net/http2.(*Framer).checkFrameOrder", fn_name="probe_http2_framer_check_frame_order")


bpf.trace_print()

"""
aliyun 内网IP 172.19.238.118 对应int值2886987382
海创园 公网IP 60.191.18.194 对应int值1019155138
"""