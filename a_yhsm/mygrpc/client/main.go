package main

import (
	"context"
	"flag"
	"log"
	"time"
	"io"
	"strconv"
	"google.golang.org/grpc"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	// "fmt"
	pb "mygrpc/proto"
)

func mustCreateGrpcClientConn(address string) *grpc.ClientConn {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithUnaryInterceptor(UnaryClientInterceptor))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

func UnaryClientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	log.Printf("before invoker. method: %+v, request:%+v", method, req)
	err := invoker(ctx, method, req, reply, cc, opts...)
	log.Printf("after invoker. reply: %+v", reply)
	return err
}

func callSimple(address, name string, count, sleep_millis int) {
	conn := mustCreateGrpcClientConn(address)
	defer conn.Close()

	c := pb.NewGreeterClient(conn)

    traceid := uuid.New().String()
    // ctx = metadata.AppendToOutgoingContext(ctx, "trace-id", traceID)
	// fmt.Println("traceID=%s", traceID)

	// md := metadata.Pairs("test_data", uuid.New().String())
	
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
		ctx = metadata.AppendToOutgoingContext(context.Background(), "traceid", traceid)
		defer cancel()
		r, err := c.Simple(ctx, &pb.HelloRequest{Name: name})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		// 从 metadata 中获取 traceid
		log.Printf("Greeting: %s", r.Message)
		log.Printf("test_data: %s", traceid)
		time.Sleep(time.Duration(sleep_millis) * time.Millisecond)
	}
}

func callSimpleToStream(address, name string, count, sleep_millis int) {
	conn := mustCreateGrpcClientConn(address)
	defer conn.Close()

	c := pb.NewGreeterClient(conn)

	req := pb.HelloRequest{
		Name: "yexm",
	}
	//获取流
	stream, err := c.SimpleToStream(context.Background(), &req)
	if err != nil {
		log.Fatalf("Call SayHello err: %v", err)
	}
	for{
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Conversations get stream err: %v", err)
		}
		// 打印返回值
		log.Println(res.Message)
	}
}

func callStreamToSimple(address, name string, count, sleep_millis int) {
	conn := mustCreateGrpcClientConn(address)
	defer conn.Close()

	// 建立gRPC连接
	grpcClient := pb.NewGreeterClient(conn)
	// 创建发送结构体

	res, err := grpcClient.StreamToSimple(context.Background())
	if err != nil {
		log.Fatalf("Call SayHello err: %v", err)
	}

	for i := 0; i < 5; i++ {
		err = res.Send(&pb.HelloRequest{Name: "stream client rpc " + strconv.Itoa(i)})
		if err != nil {
			log.Fatalf("stream request err: %v", err)
			return
		}
	}
	// 打印返回值
	log.Println(res.CloseAndRecv())
}

func main() {
	address := flag.String("address", "localhost:50051", "Server end point.")
	name := flag.String("name", "world", "The name to greet.")
	typ := flag.Int("type", 1, "The type of RPC calls to make.")
	sleep_millis := flag.Int("sleep-millis", 500, "The number of milliseconds to sleep between RPC calls.")
	flag.Parse()
	if *typ == 1 {
		callSimple(*address, *name, *typ, *sleep_millis)
	} else if *typ == 2{
		callSimpleToStream(*address, *name, *typ, *sleep_millis)
	} else if *typ == 3{
		callStreamToSimple(*address, *name, *typ, *sleep_millis)
	} else {
		log.Println("error type");
	}
}
