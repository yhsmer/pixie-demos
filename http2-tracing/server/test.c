#include <uapi/linux/ptrace.h>
#include <net/sock.h>

enum location_type_t {
  kLocationTypeInvalid = 0,
  kLocationTypeStack = 1,
  kLocationTypeRegisters = 2
};

struct location_t {
  enum location_type_t type;
  int32_t offset;
};

struct go_regabi_regs {
  uint64_t regs[9];
};

struct go_interface {
  int64_t type;
  void* ptr;
};

// The BPF map used to store the registers of Go's register-based calling convention.
BPF_PERCPU_ARRAY(regs_heap, struct go_regabi_regs, 1);

// Copies the registers of the golang ABI, so that they can be
// easily accessed using an offset.
static __inline uint64_t* go_regabi_regs(const struct pt_regs* ctx) {
//   uint32_t kZero = 0;
//   struct go_regabi_regs* regs_heap_var = regs_heap.lookup(&kZero);
//   if (regs_heap_var == NULL) {
//     return NULL;
//   }
  
  struct go_regabi_regs regs_heap;

  struct go_regabi_regs* regs_heap_var = &regs_heap;
  regs_heap_var->regs[0] = ctx->ax;
  regs_heap_var->regs[1] = ctx->bx;
  regs_heap_var->regs[2] = ctx->cx;
  regs_heap_var->regs[3] = ctx->di;
  regs_heap_var->regs[4] = ctx->si;
  regs_heap_var->regs[5] = ctx->r8;
  regs_heap_var->regs[6] = ctx->r9;
  regs_heap_var->regs[7] = ctx->r10;
  regs_heap_var->regs[8] = ctx->r11;

  return regs_heap_var->regs;
}


// Reads a golang function argument, taking into account the ABI.
// Go arguments may be in registers or on the stack.
static __inline void assign_arg(void* arg, size_t arg_size, struct location_t loc, const void* sp,
                                uint64_t* regs) {
  if (loc.type == kLocationTypeStack) {
    bpf_probe_read(arg, arg_size, sp + loc.offset);
  } else if (loc.type == kLocationTypeRegisters) {
    if (loc.offset >= 0) {
      bpf_probe_read(arg, arg_size, (char*)regs + loc.offset);
    }
  }
}

// ----------------------------------------------------

// fd
static __inline int32_t get_fd_from_conn_intf_core(struct go_interface conn_intf) {

  // bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_intf.ptr + 0);

  void* fd_ptr;
  bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);

  int64_t sysfd;
  bpf_probe_read(&sysfd, sizeof(int64_t), fd_ptr + 16);

  bpf_trace_printk("fdddd: %d\n", sysfd);

  return sysfd;
}

static __inline int32_t get_fd_from_conn_intf(struct go_interface conn_intf) {
  uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

  return get_fd_from_conn_intf_core(conn_intf);
}

// ----------------------------------------------------

// Probe for the golang.org/x/net/http2 library's header reader (server-side).
//
// Function signature:
//   func (t *http2Server) operateHeaders(frame *http2.MetaHeadersFrame, handle func(*Stream),
//                                        traceCtx func(context.Context, string) context.Context
//                                        (fatal bool)
// Symbol:
//   google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders
// solved
int probe_http2_server_operate_headers(struct pt_regs* ctx) {
  uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

  // ---------------------------------------------
  // Extract arguments
  // ---------------------------------------------
  const void* sp = (const void*)ctx->sp;
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  void* http2_server_ptr = NULL;
  struct location_t http2Server_operateHeaders_t_loc;
  http2Server_operateHeaders_t_loc.type = kLocationTypeStack;
  http2Server_operateHeaders_t_loc.offset = 8;
  assign_arg(&http2_server_ptr, sizeof(http2_server_ptr),
             http2Server_operateHeaders_t_loc , sp, regs);

  void* frame_ptr = NULL;
  struct location_t http2Server_operateHeaders_frame_loc;
  http2Server_operateHeaders_frame_loc.type = kLocationTypeStack;
  http2Server_operateHeaders_frame_loc.offset = 24;
  assign_arg(&frame_ptr, sizeof(frame_ptr), http2Server_operateHeaders_t_loc, sp,
             regs);

  // ---------------------------------------------
  // Extract members
  // ---------------------------------------------

  struct go_interface conn_intf;
  // 16 or 24
  bpf_probe_read(&conn_intf, sizeof(conn_intf),
                 http2_server_ptr + 16);

  const int32_t fd = get_fd_from_conn_intf(conn_intf);
  bpf_trace_printk("fd(conn_intf): %d\n", fd);
  
  if (fd == -1) {
    return 0;
  }

  //probe_http2_operate_headers(ctx, k_probe_http2_server_operate_headers, fd, frame_ptr, symaddrs);

  return 0;
}

static __inline int32_t get_fd_from_http2_Framer(const void* framer_ptr) {
  struct go_interface io_writer_interface;
  bpf_probe_read(&io_writer_interface, sizeof(io_writer_interface),
                 framer_ptr + 112);

  // At this point, we have the following struct:
  // go.itab.*google.golang.org/grpc/internal/transport.bufWriter,io.Writer
  // if (io_writer_interface.type != 1) {
  //   bpf_trace_printk("io_writer_interface.type ERROR \n");
  //   //return -1;
  // }

  struct go_interface conn_intf;
  bpf_probe_read(&conn_intf, sizeof(conn_intf),
                 io_writer_interface.ptr + 40);

  return get_fd_from_conn_intf(conn_intf);
}

int probe_http2_framer_check_frame_order(struct pt_regs* ctx) {
  // ---------------------------------------------
  // Extract arguments
  // ---------------------------------------------

  const void* sp = (const void*)ctx->sp;

  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  void* framer_ptr = NULL;
  struct location_t http2_checkFrameOrder_fr_loc;
  http2_checkFrameOrder_fr_loc.type = kLocationTypeStack;
  http2_checkFrameOrder_fr_loc.offset = 8;
  assign_arg(&framer_ptr, sizeof(framer_ptr), http2_checkFrameOrder_fr_loc, sp, regs);

  int32_t fd = get_fd_from_http2_Framer(framer_ptr);
  
  bpf_trace_printk("fd (Frame): %d\n", fd);

  // struct socket *sock;
	// struct sockaddr_storage address;
	// int err, fput_needed;

	// sock = sockfd_lookup_light(fd, &err, &fput_needed);

  return 0;
}
