package main

import "fmt"

type Reader interface {
	Read() int
}

type MyStruct struct {
	X, Y int
}

func (m *MyStruct) Read() int {
	return m.X + m.Y
}

func run(r Reader) {
	fmt.Println(r.Read())
}

func main() {
	s := &MyStruct{3, 4}
	run(s)
}
