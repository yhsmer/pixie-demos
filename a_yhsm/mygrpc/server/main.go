package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strconv"
	"io"
	"google.golang.org/grpc"
	pb "mygrpc/proto"
)

type server struct{
	pb.UnimplementedGreeterServer
}


func (s *server) Simple(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
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

	s := grpc.NewServer()

	log.Printf("Launching unary server")
	pb.RegisterGreeterServer(s, &server{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
