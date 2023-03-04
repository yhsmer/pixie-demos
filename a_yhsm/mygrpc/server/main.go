package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strconv"
	"io"
	"google.golang.org/grpc"
	"fmt"
	// "github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	pb "mygrpc/proto"
)

type server struct{
	pb.UnimplementedGreeterServer
}

func traceInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    // // 生成一个随机的 traceID
    // traceID := uuid.New().String()
    // // 将 traceID 添加到上下文中
    // ctx = metadata.AppendToOutgoingContext(ctx, "trace-id", traceID)
    // // 调用 gRPC 服务的处理函数

	// log.Printf("before handling. Info: %+v", info)


	// md, ok := metadata.FromIncomingContext(ctx)
	// if !ok {
	// 	md = metadata.Pairs()
	// }
	// // Set request ID for context.
	// requestIDs := md[string(trace.RequestID)]
	// if len(requestIDs) >= 1 {
	// 	ctx = context.WithValue(ctx, trace.RequestID, requestIDs[0])
	// 	return handler(ctx, req)
	// }

	// // Generate request ID and set context if not exists.
	// requestID := id.NewHex32()
	// ctx = context.WithValue(ctx, trace.RequestID, requestID)

	resp, err := handler(ctx, req)
	log.Printf("after handling. resp: %+v", resp)

    return resp, err
}


func (s *server) Simple(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
	md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, fmt.Errorf("failed to get metadata from context")
    }
    traceID := md["traceid"]

    // 打印 traceID 和请求内容
    log.Printf("received request with traceID=%s, name=%s\n", traceID, in.Name)
	return &pb.HelloReply{Message: "(Simple)Hello " + in.Name}, nil
}


func (s *server) SimpleToStream(request *pb.HelloRequest, server pb.Greeter_SimpleToStreamServer) error {
    for n := 0; n < 5; n++ {
        // 向流中发送消息， 默认每次send送消息最大长度为`math.MaxInt32`bytes 
        err := server.Send(&pb.HelloReply{Message: "(SimpleToStream)Hello " + request.Name + " " + strconv.Itoa(n)})
        if err != nil {
            return err
        }
    }
    return nil
}

func (s *server) StreamToSimple(server pb.Greeter_StreamToSimpleServer) error {
	for {
		//从流中获取消息
		res, err := server.Recv()
		if err == io.EOF {
			//发送结果，并关闭
			return server.SendAndClose(&pb.HelloReply{Message: "(StreamToSimple)server received all"})
		}
		if err != nil {
			return err
		}
		log.Println(res.Name)
	}
}


func main() {
	port := flag.Int("port", 50051, "The port to listen.")
	flag.Parse()

	log.Printf("Starting http server on port: %d", *port)
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(*port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(traceInterceptor),
	)

	log.Printf("Launching unary server")
	pb.RegisterGreeterServer(s, &server{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
