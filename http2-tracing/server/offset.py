# -*- coding: UTF-8 -*-
from bcc import BPF

src = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/fdtable.h>
#include <net/inet_sock.h>
inline int parse(struct pt_regs *ctx){
    const void *sp = (const void *)ctx->sp;
    long a;
    bpf_probe_read(&a, sizeof(a), sp + 8);
    bpf_trace_printk("%d\n", a);

    char b;
    bpf_probe_read(&b, sizeof(b), sp + 16);
    bpf_trace_printk("%d\n", b);
    
    u32 c;
    bpf_probe_read(&c, sizeof(c), sp + 20);
    bpf_trace_printk("%d\n", c);

    return 0;
}
"""

bpf = BPF(text=src)

bpf.attach_uprobe(
    name="./offset",
    sym="main.fun",
    fn_name="parse")

bpf.trace_print()