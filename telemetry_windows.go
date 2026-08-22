//go:build windows

package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func nebulaServiceState() (exists, running bool) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString("Nebula")
	if err != nil {
		return false, false
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return true, false
	}
	return true, status.CurrentState == windows.SERVICE_RUNNING
}

func readLocalTelemetry() (received, sent uint64, running bool) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err == nil && table != nil {
		defer windows.FreeMibTable(unsafe.Pointer(table))
		rows := unsafe.Slice(&table.Table[0], int(table.NumEntries))
		for index := range rows {
			row := &rows[index]
			if strings.EqualFold(windows.UTF16ToString(row.Alias[:]), "MeshLAN") {
				return row.InOctets, row.OutOctets, row.OperStatus == windows.IfOperStatusUp
			}
		}
	}
	_, running = nebulaServiceState()
	return 0, 0, running
}
