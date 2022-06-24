#include <uapi/linux/ptrace.h>
struct data_t
{
    int a;
    char b;
    u32 c;
    char msg[128];
};

BPF_PERF_OUTPUT(events);
inline int get_parseMe(struct pt_regs *ctx) {
		void* stackAddr = (void*)ctx->sp;

        struct data_t data = {};

		long argument1;
		bpf_probe_read(&argument1, sizeof(argument1), stackAddr+8);
		//events.perf_submit(ctx, &argument1, sizeof(argument1));
        bpf_trace_printk("a: %d\n", argument1);

		char argument2;
		bpf_probe_read(&argument2, sizeof(argument2), stackAddr+8 + 8); 
		//events.perf_submit(ctx, &argument2, sizeof(argument2));
        bpf_trace_printk("b: %d\n", argument2);

		u32 argument3;
		bpf_probe_read(&argument3, sizeof(argument3) , stackAddr+8 + 12); 
        // data.a = argument1;
        // data.b = argument2;
        // data.c = argument3;
		// events.perf_submit(ctx, &data, sizeof(data));
        bpf_trace_printk("c: %d\n", argument3);

        long argument4;
		bpf_probe_read(&argument4, sizeof(argument4), stackAddr+8 + 16);
		//events.perf_submit(ctx, &argument1, sizeof(argument1));
        bpf_trace_printk("d: %d\n", argument4);
        return 0;
}

inline int get_forString(struct pt_regs *ctx){
    void* sp = (void*)ctx->sp;
    // string的地址
    void* string_ptr = NULL;
    bpf_probe_read(&string_ptr, sizeof(string_ptr), sp + 8 + 8);
    // string的长度
    int64_t string_len = 0;
    bpf_probe_read(&string_len, sizeof(string_len), sp + 8 + 16);
    // 从堆栈中获取的值无法确定大小，需要进行逻辑运算保证变量的范围，不然无法通过bpf验证器
    if (string_len > 128) string_len = 128;
    if (string_len < 0) string_len = 0;
    
    struct data_t data = {};
    // 再一次 bpf_probe_read才能读出真正的数据
    bpf_probe_read(&data.msg, string_len, string_ptr);
    
    bpf_trace_printk("value: %s\n", data.msg);

    // 对于指针堆栈中只存了地址
    void* u32_ptr = NULL;
    bpf_probe_read(&u32_ptr, sizeof(u32_ptr), sp + 8);
    // 由于堆栈中只存了地址，需要自己判断指针指向的是什么数据类型
    bpf_probe_read(&data.c, sizeof(data.c), u32_ptr);
    bpf_trace_printk("%d\n", data.c);

    return 0;
}

inline int get_forComplex(struct pt_regs *ctx){
    void* sp = (void*)ctx->sp;
    long a ;
    bpf_probe_read(&a, sizeof(a), sp + 8);
    bpf_trace_printk("%d\n", a);

    long b;
    bpf_probe_read(&b, sizeof(b), sp + 8 + 32);
    bpf_trace_printk("%d\n", b);
    return 0;
}

inline int get_forArray(struct pt_regs *ctx){
    bpf_trace_printk("forArray\n");

    void* sp = (void*)ctx->sp;

    void* array_ptr = NULL;
    bpf_probe_read(&array_ptr, sizeof(array_ptr), sp + 8);

    long a;
    bpf_probe_read(&a, sizeof(a), array_ptr);
    bpf_trace_printk("%d\n", a);

    bpf_probe_read(&a, sizeof(a), array_ptr + 8);
    bpf_trace_printk("%d\n", a);
    return 0;
}

inline int get_forSlice(struct pt_regs *ctx){
    bpf_trace_printk("forSlice\n");

    void* sp = (void*)ctx->sp;
    
    void* array_ptr = NULL;
    bpf_probe_read(&array_ptr, sizeof(array_ptr), sp + 8);

    long a;
    bpf_probe_read(&a, sizeof(a), array_ptr);
    bpf_trace_printk("%d\n", a);

    bpf_probe_read(&a, sizeof(a), array_ptr + 8);
    bpf_trace_printk("%d\n", a);

    bpf_probe_read(&a,sizeof(a), sp + 8 + 8);
    bpf_trace_printk("%d\n", a);

    bpf_probe_read(&a,sizeof(a), sp + 8 + 16);
    bpf_trace_printk("%d\n", a);
    return 0;
}

inline int get_forInterface(struct pt_regs *ctx){
    bpf_trace_printk("forInterface\n");

    void* sp = (void*)ctx->sp;
   
    void* ptr = NULL;
    bpf_probe_read(&ptr, sizeof(ptr), sp + 8 + 8);

    long a;
    bpf_probe_read(&a, sizeof(a), ptr);
    bpf_trace_printk("%d\n", a);


    bpf_probe_read(&a,sizeof(a), ptr + 8);
    bpf_trace_printk("%d\n", a);
    return 0;
}