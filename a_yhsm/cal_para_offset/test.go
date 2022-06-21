package main

import "fmt"

type Books struct {
	a int
	b string
	c *int
}

//go:noinline
func parseMe(a int, b bool, c int32, d int) int {
	e := 89
	fmt.Println(e)
	return e
	// some code
}

//go:noinline
func forComplex(book Books, z int) string {
	fmt.Println(*book.c)
	fmt.Println(book)
	//fmt.Println(x)
	//fmt.Printf("%d\n", *y)
	return book.b
}

//go:noinline
func forString(a *int32, s string) string {
	fmt.Println(*a)
	fmt.Println(s)
	return s
}

//go:noinline
func forArray(arr *[5]int) int {
	fmt.Println(&arr)
	fmt.Println("forArray")
	s := 0
	for i := 0; i < len(arr); i++ {
		fmt.Println(&arr[i])
		s += arr[i]
	}
	fmt.Println(s)
	return s
}

//go:noinline
func forSlice(arr []int) int {
	fmt.Println(&arr)
	fmt.Println("forSlice")
	s := 0
	for i := 0; i < len(arr); i++ {
		fmt.Println(&arr[i])
		s += arr[i]
	}
	fmt.Println(s)
	return s
}

func main() {
	//parseMe(1, false, 2, 3)
	//x := "yexm"
	y := 22
	z := 100
	var arr = [5]int{22, 45, 67, 25, 98}
	book := Books{
		90,
		"zju",
		nil,
	}
	if book.c == nil {
		book.c = &z
	}
	//var a int32 = 23
	//forString(&a, x)
	re := forComplex(book, y)
	fmt.Println("returnd : " + re)
	for i := 0; i < len(arr); i++ {
		fmt.Println(&arr[i])
	}
	fmt.Printf("%p\n", &arr)
	fmt.Println("in main")
	forArray(&arr)
	forSlice(arr[:])
}
