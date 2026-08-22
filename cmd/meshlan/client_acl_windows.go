//go:build windows

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

func currentUserSIDString() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", errors.New("无法读取当前Windows用户SID")
	}
	return user.User.Sid.String(), nil
}

func clientSecretACLArguments(root, userSID string) []string {
	return []string{
		root, "/inheritance:r", "/grant:r",
		"*" + userSID + ":(OI)(CI)(F)",
		"*S-1-5-18:(OI)(CI)(F)",
		"/C", "/Q",
	}
}

func clientSecretChildResetArguments(root string) []string {
	return []string{root + `\*`, "/reset", "/T", "/C", "/Q"}
}

func hardenClientSecretDirectory(root string) error {
	userSID, err := currentUserSIDString()
	if err != nil {
		return err
	}
	cmd := exec.Command("icacls.exe", clientSecretACLArguments(root, userSID)...)
	hidden(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("收紧客户端秘密目录ACL失败: %s", strings.TrimSpace(string(output)))
	}
	reset := exec.Command("icacls.exe", clientSecretChildResetArguments(root)...)
	hidden(reset)
	resetOutput, err := reset.CombinedOutput()
	if err != nil {
		return fmt.Errorf("重建客户端秘密文件继承ACL失败: %s", strings.TrimSpace(string(resetOutput)))
	}
	return nil
}

func clientSecretACLHardened(root string) bool {
	cmd := exec.Command("icacls.exe", root)
	hidden(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	text := strings.ToLower(string(output))
	return !strings.Contains(text, "codexsandboxusers") && strings.Contains(text, "system")
}
