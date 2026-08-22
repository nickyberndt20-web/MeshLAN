package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	if len(os.Args) < 2 {
		if runtime.GOOS == "windows" {
			if err := clientMain(nil); err != nil {
				fmt.Fprintln(os.Stderr, "错误：", err)
				os.Exit(1)
			}
			return
		}
		fmt.Fprintln(os.Stderr, "用法：mesh-lan-nebula client | server <命令>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "client":
		err = clientMain(os.Args[2:])
	case "server":
		err = serverMain(os.Args[2:])
	default:
		err = fmt.Errorf("未知模式：%s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}
