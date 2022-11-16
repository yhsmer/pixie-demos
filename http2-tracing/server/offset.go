package main

//go:noinline
func fun(a int, b bool, c int32) {
	return
}

func main() {
	fun(1999, true, 2008)
}
