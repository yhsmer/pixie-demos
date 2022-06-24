# -*- coding: UTF-8 -*-
from bcc import BPF
#from bcc.utils import printb

f = open("bpf.c", encoding="utf-8")
bpf_source = f.read()

bpf = BPF(text=bpf_source)
#bpf.attach_uprobe(name="./test", sym="main.parseMe", fn_name="get_parseMe")
#bpf.attach_uprobe(name="./test", sym="main.forComplex", fn_name="get_forComplex")
#bpf.attach_uprobe(name="./test", sym="main.forString", fn_name="get_forString")
#bpf.attach_uprobe(name="./test", sym="main.forComplex", fn_name="get_forComplex")
#bpf.attach_uprobe(name="./test", sym="main.forArray", fn_name="get_forArray")
# bpf.attach_uprobe(na=me="./test", sym="main.forSlice", fn_name="get_forSlice")
bpf.attach_uprobe(name="./interface", sym="main.run", fn_name="get_forInterface")


output = 1;
if output:
    bpf.trace_print()
else:
    # header
    print("DATA: ")

    def print_event(cpu, data, size):
        event = bpf["events"].event(data)
        print("%-10d %-10d %-10d" % (event.a, event.b, event.c))

    # loop with callback to print_event
    bpf["events"].open_perf_buffer(print_event)
    while 1:
        try:
            bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()