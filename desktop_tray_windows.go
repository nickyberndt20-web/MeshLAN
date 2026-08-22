//go:build windows

package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const (
	nativeGWLPWndProc   = ^uintptr(3) // -4
	nativeWMClose       = 0x0010
	nativeWMDestroy     = 0x0002
	nativeWMAppTray     = 0x8001
	nativeWMLButtonUp   = 0x0202
	nativeWMLButtonDbl  = 0x0203
	nativeWMRButtonUp   = 0x0205
	nativeSWRestore     = 9
	nativeSWHide        = 0
	nativeNIMAdd        = 0
	nativeNIMDelete     = 2
	nativeNIFMessage    = 0x1
	nativeNIFIcon       = 0x2
	nativeNIFTip        = 0x4
	nativeImageIcon     = 1
	nativeLRDefaultSize = 0x40
	nativeLRShared      = 0x8000
	nativeMFString      = 0
	nativeTPMReturnCmd  = 0x100
	nativeTPMRight      = 0x2
	nativeMenuOpen      = 1001
	nativeMenuExit      = 1002
)

type nativeTrayPoint struct{ X, Y int32 }

type nativeNotifyIconData struct {
	CbSize           uint32
	HWnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	Version          uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

type nativeTrayContext struct {
	window       webview2.WebView
	hwnd         uintptr
	originalProc uintptr
	notify       nativeNotifyIconData
	exiting      atomic.Bool
}

var (
	nativeTrayShell32         = windows.NewLazySystemDLL("shell32.dll")
	nativeTrayUser32          = windows.NewLazySystemDLL("user32.dll")
	nativeShellNotifyIconW    = nativeTrayShell32.NewProc("Shell_NotifyIconW")
	nativeSetWindowLongPtrW   = nativeTrayUser32.NewProc("SetWindowLongPtrW")
	nativeCallWindowProcW     = nativeTrayUser32.NewProc("CallWindowProcW")
	nativeCreatePopupMenu     = nativeTrayUser32.NewProc("CreatePopupMenu")
	nativeAppendMenuW         = nativeTrayUser32.NewProc("AppendMenuW")
	nativeTrackPopupMenu      = nativeTrayUser32.NewProc("TrackPopupMenu")
	nativeDestroyMenu         = nativeTrayUser32.NewProc("DestroyMenu")
	nativeGetCursorPos        = nativeTrayUser32.NewProc("GetCursorPos")
	nativePostMessageW        = nativeTrayUser32.NewProc("PostMessageW")
	nativeLoadImageW          = nativeTrayUser32.NewProc("LoadImageW")
	nativeTrayContexts        = map[uintptr]*nativeTrayContext{}
	nativeTrayContextsMu      sync.RWMutex
	nativeTrayWindowProcedure = windows.NewCallback(nativeTrayWndProc)
)

func nativeTrayContextFor(hwnd uintptr) *nativeTrayContext {
	nativeTrayContextsMu.RLock()
	defer nativeTrayContextsMu.RUnlock()
	return nativeTrayContexts[hwnd]
}

func nativeTraySetContext(hwnd uintptr, context *nativeTrayContext) {
	nativeTrayContextsMu.Lock()
	defer nativeTrayContextsMu.Unlock()
	if context == nil {
		delete(nativeTrayContexts, hwnd)
	} else {
		nativeTrayContexts[hwnd] = context
	}
}

func nativeTrayShow(context *nativeTrayContext) {
	_, _, _ = nativeShowWindow.Call(context.hwnd, nativeSWRestore)
	_, _, _ = nativeSetForegroundWindow.Call(context.hwnd)
}

func nativeTrayMenu(context *nativeTrayContext) {
	menu, _, _ := nativeCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer nativeDestroyMenu.Call(menu)
	openText, _ := windows.UTF16PtrFromString("打开 MeshLAN")
	exitText, _ := windows.UTF16PtrFromString("退出")
	_, _, _ = nativeAppendMenuW.Call(menu, nativeMFString, nativeMenuOpen, uintptr(unsafe.Pointer(openText)))
	_, _, _ = nativeAppendMenuW.Call(menu, nativeMFString, nativeMenuExit, uintptr(unsafe.Pointer(exitText)))
	var point nativeTrayPoint
	_, _, _ = nativeGetCursorPos.Call(uintptr(unsafe.Pointer(&point)))
	_, _, _ = nativeSetForegroundWindow.Call(context.hwnd)
	command, _, _ := nativeTrackPopupMenu.Call(menu, nativeTPMReturnCmd|nativeTPMRight, uintptr(point.X), uintptr(point.Y), 0, context.hwnd, 0)
	switch command {
	case nativeMenuOpen:
		nativeTrayShow(context)
	case nativeMenuExit:
		context.exiting.Store(true)
		_, _, _ = nativePostMessageW.Call(context.hwnd, nativeWMClose, 0, 0)
	}
}

func nativeTrayWndProc(hwnd, message, wParam, lParam uintptr) uintptr {
	context := nativeTrayContextFor(hwnd)
	if context == nil {
		return 0
	}
	switch message {
	case nativeWMClose:
		if !context.exiting.Load() {
			_, _, _ = nativeShowWindow.Call(hwnd, nativeSWHide)
			return 0
		}
	case nativeWMAppTray:
		switch lParam {
		case nativeWMLButtonUp, nativeWMLButtonDbl:
			nativeTrayShow(context)
		case nativeWMRButtonUp:
			nativeTrayMenu(context)
		}
		return 0
	case nativeWMDestroy:
		_, _, _ = nativeShellNotifyIconW.Call(nativeNIMDelete, uintptr(unsafe.Pointer(&context.notify)))
		nativeTraySetContext(hwnd, nil)
	}
	result, _, _ := nativeCallWindowProcW.Call(context.originalProc, hwnd, message, wParam, lParam)
	return result
}

func installNativeTray(window webview2.WebView) (func(), error) {
	hwnd := uintptr(window.Window())
	if hwnd == 0 {
		return func() {}, errors.New("MeshLAN窗口句柄无效")
	}
	original, _, callErr := nativeSetWindowLongPtrW.Call(hwnd, nativeGWLPWndProc, nativeTrayWindowProcedure)
	if original == 0 && callErr != windows.ERROR_SUCCESS {
		return func() {}, callErr
	}
	var module windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &module)
	icon, _, _ := nativeLoadImageW.Call(uintptr(module), 2, nativeImageIcon, 0, 0, nativeLRDefaultSize|nativeLRShared)
	context := &nativeTrayContext{window: window, hwnd: hwnd, originalProc: original}
	context.notify.CbSize = uint32(unsafe.Sizeof(context.notify))
	context.notify.HWnd = windows.Handle(hwnd)
	context.notify.UID = 1
	context.notify.UFlags = nativeNIFMessage | nativeNIFIcon | nativeNIFTip
	context.notify.UCallbackMessage = nativeWMAppTray
	context.notify.HIcon = windows.Handle(icon)
	tip, _ := windows.UTF16FromString("MeshLAN · P2P虚拟局域网")
	copy(context.notify.SzTip[:], tip)
	nativeTraySetContext(hwnd, context)
	added, _, addErr := nativeShellNotifyIconW.Call(nativeNIMAdd, uintptr(unsafe.Pointer(&context.notify)))
	if added == 0 {
		nativeTraySetContext(hwnd, nil)
		_, _, _ = nativeSetWindowLongPtrW.Call(hwnd, nativeGWLPWndProc, original)
		if addErr != windows.ERROR_SUCCESS {
			return func() {}, addErr
		}
		return func() {}, errors.New("无法创建 MeshLAN系统托盘图标")
	}
	cleanup := func() {
		_, _, _ = nativeShellNotifyIconW.Call(nativeNIMDelete, uintptr(unsafe.Pointer(&context.notify)))
		nativeTraySetContext(hwnd, nil)
		_, _, _ = nativeSetWindowLongPtrW.Call(hwnd, nativeGWLPWndProc, original)
	}
	return cleanup, nil
}
