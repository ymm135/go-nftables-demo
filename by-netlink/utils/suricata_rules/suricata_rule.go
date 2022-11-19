package suricatarules

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	WHITE_LIST = "whitelist"
	BLACK_LIST = "blacklist"
	SURICATA   = "suricata"
)

func getShellFilePath() string {
	path, _ := os.Executable()
	dir := filepath.Dir(path)
	return dir + "/shell/suricata_vtysh.sh"
}

func AddWhiteList(rule string) {
	err := GoLinuxCommonds(getShellFilePath(), WHITE_LIST, "add", "'"+rule+"'")
	if err != nil {
		fmt.Println("error:", err.Error())
	}
}

func DelWhiteList() {
	err := GoLinuxCommonds(getShellFilePath(), WHITE_LIST, "del")
	if err != nil {
		fmt.Println("error:", err.Error())
	}
}

func AddBlackList(rule string) {
	err := GoLinuxCommonds(getShellFilePath(), BLACK_LIST, "add", "'"+rule+"'")
	if err != nil {
		fmt.Println("error:", err.Error())
	}
}

func DelBlackList() {
	err := GoLinuxCommonds(getShellFilePath(), BLACK_LIST, "del")
	if err != nil {
		fmt.Println("error:", err.Error())
	}
}

func ReloadRules() {
	err := GoLinuxCommonds(getShellFilePath(), SURICATA, "reload")
	if err != nil {
		fmt.Println("error:", err.Error())
	}
}
