//go:build !windows

package main

import "errors"

func clientMain(_ []string) error { return errors.New("客户端目前只支持 Windows") }
