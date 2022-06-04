# -*- coding: UTF-8 -*-
from bcc import BPF
from bcc.utils import printb

f = open("client_bpf_uprobe.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="./grpc_client", sym="google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders", fn_name="probe_http2_client_operate_headers")
bpf.attach_uprobe(name="./grpc_client", sym="golang.org/x/net/http2/hpack.(*Encoder).WriteField", fn_name="probe_hpack_header_encoder")
bpf.attach_uprobe(name="./grpc_client", sym="golang.org/x/net/http2.(*Framer).checkFrameOrder", fn_name="probe_http2_framer_check_frame_order")

output = 0;
if output:
    bpf.trace_print()
else:
    # header
    print("%-10s %-18s %-18s" % ("KEY", "VALUE(INT)", "VALUE(CHAR*)"))

    def print_event(cpu, data, size):
        event = bpf["go_http2_header_events"].event(data)
        printb(b"%-10s %-18d %-18s" % (event.name, event.int_value, event.char_value))

    # loop with callback to print_event
    bpf["go_http2_header_events"].open_perf_buffer(print_event)
    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()