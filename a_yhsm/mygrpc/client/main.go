package main

import (
	"context"
	"flag"
	"log"
	"time"
	"io"
	"strconv"
	"google.golang.org/grpc"

	pb "mygrpc/proto"
)

func mustCreateGrpcClientConn(address string) *grpc.ClientConn {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

func callSimple(address, name string, count, sleep_millis int) {
	conn := mustCreateGrpcClientConn(address)
	defer conn.Close()

	c := pb.NewGreeterClient(conn)

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
		defer cancel()
		r, err := c.Simple(ctx, &pb.HelloRequest{Name: name})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		log.Printf("Greeting: %s", r.Message)
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
