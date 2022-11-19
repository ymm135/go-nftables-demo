package suricatarules

import (
	"fmt"
	"strings"

	"github.com/progrium/go-shell"
)

func GoLinuxCommonds(cmd ...string) error {
	cmdStr := strings.Join(cmd, " ")
	process := shell.Cmd(cmdStr).Run()
	fmt.Println(process)
	return process.Error()
}
