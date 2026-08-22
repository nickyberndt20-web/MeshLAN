//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const nativeDesktopTitle = "MeshLAN"

var (
	nativeUser32              = windows.NewLazySystemDLL("user32.dll")
	nativeFindWindowW         = nativeUser32.NewProc("FindWindowW")
	nativeShowWindow          = nativeUser32.NewProc("ShowWindow")
	nativeSetForegroundWindow = nativeUser32.NewProc("SetForegroundWindow")
)

func focusExistingNativeWindow() {
	className, _ := windows.UTF16PtrFromString("webview")
	title, _ := windows.UTF16PtrFromString(nativeDesktopTitle)
	handle, _, _ := nativeFindWindowW.Call(uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)))
	if handle == 0 {
		return
	}
	_, _, _ = nativeShowWindow.Call(handle, 9) // SW_RESTORE
	_, _, _ = nativeSetForegroundWindow.Call(handle)
}

func runNativeDesktopWindow(targetURL, dataPath string) error {
	mutexName, _ := windows.UTF16PtrFromString(`Local\MeshLAN-Native-Desktop`)
	mutex, mutexErr := windows.CreateMutex(nil, false, mutexName)
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if errors.Is(mutexErr, windows.ERROR_ALREADY_EXISTS) {
		focusExistingNativeWindow()
		return nil
	}
	if mutexErr != nil {
		return mutexErr
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		return err
	}
	window := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug: false, DataPath: filepath.Clean(dataPath), AutoFocus: true,
		WindowOptions: webview2.WindowOptions{Title: nativeDesktopTitle, Width: 1280, Height: 860, IconId: 2, Center: true},
	})
	if window == nil {
		return errors.New("无法创建 MeshLAN 原生窗口；请安装 Microsoft Edge WebView2 Runtime")
	}
	defer window.Destroy()
	window.SetSize(980, 680, webview2.HintMin)
	cleanupTray, err := installNativeTray(window)
	if err != nil {
		return err
	}
	defer cleanupTray()
	window.Init(`document.documentElement.dataset.meshNativeDesktop="true";`)
	window.Navigate(targetURL)
	window.Run()
	return nil
}
