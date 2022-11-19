package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	suricatarules "netvine.com/firewall/server/utils/suricata_rules"

	"github.com/urfave/cli/v2"
	"netvine.com/firewall/server/model"
	"netvine.com/firewall/server/service"
)

// main
// --sregion eth0,eth1 --dregion eth2,eth3 --sip 192.168.0.1/24 -dip 192.168.0.1/24 -smac 0c:73:eb:92:80:cf -dmac 0c:73:eb:92:80:cf --protocol tcp --sport 22 --app modbus --time-type day --time-value 0-6 --action drop
func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "version",
				Aliases: []string{"V"},
				Usage:   "查看版本",
				Action: func(cCtx *cli.Context) error {
					fmt.Fprintf(cCtx.App.Writer, "fd-cmd v1.0\n")
					return nil
				},
			},
			{
				Name:    "whitelist",
				Aliases: []string{"wl"},
				Usage:   "白名单模块",
				Subcommands: []*cli.Command{
					{
						Name:  "add",
						Usage: "增加白名单",
						Action: func(cCtx *cli.Context) error {
							rule := cCtx.Args().First()
							fmt.Println("新增白名单规则:", rule)
							suricatarules.AddWhiteList(rule)
							return nil
						},
					},
					{
						Name:  "list",
						Usage: "查看白名单",
						Action: func(cCtx *cli.Context) error {
							fmt.Println("白名单列表为:", cCtx.Args().First())
							return nil
						},
					},
					{
						Name:  "del",
						Usage: "清空所有白名单",
						Action: func(cCtx *cli.Context) error {
							fmt.Println("白名单已清空")
							suricatarules.DelWhiteList()
							return nil
						},
					},
				},
			},
			{
				Name:    "backlist",
				Aliases: []string{"bl"},
				Usage:   "黑名单",
				Subcommands: []*cli.Command{
					{
						Name:  "add",
						Usage: "增加黑名单",
						Action: func(cCtx *cli.Context) error {
							rule := cCtx.Args().First()
							fmt.Println("新增黑名单规则:", rule)
							suricatarules.AddBlackList(rule)
							return nil
						},
					},
					{
						Name:  "list",
						Usage: "查看黑名单",
						Action: func(cCtx *cli.Context) error {
							fmt.Println("黑名单列表为:", cCtx.Args().First())
							return nil
						},
					},
					{
						Name:  "del",
						Usage: "清空所有黑名单",
						Action: func(cCtx *cli.Context) error {
							fmt.Println("黑名单已清空")
							suricatarules.DelBlackList()
							return nil
						},
					},
				},
			},
			{
				Name:    "suricata",
				Aliases: []string{"sc"},
				Usage:   "suricata",
				Subcommands: []*cli.Command{
					{
						Name:  "reload",
						Usage: "规则重载",
						Action: func(cCtx *cli.Context) error {
							fmt.Println("suricata 规则重载")
							suricatarules.ReloadRules()
							return nil
						},
					},
				},
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "sregion", Aliases: []string{"sr"}, Usage: "源区域: --sregion eth0,eth1"},
			&cli.StringFlag{Name: "dregion", Aliases: []string{"dr"}, Usage: "目的区域: --dregion eth0,eth1"},
			&cli.StringFlag{Name: "sip", Usage: "源IP: --sip 192.168.0.1/24"},
			&cli.StringFlag{Name: "dip", Usage: "目的IP: --dip 192.168.0.1/24"},
			&cli.StringFlag{Name: "smac", Usage: "源MAC: --smac 0c:73:eb:92:80:cf"},
			&cli.StringFlag{Name: "dmac", Usage: "目的MAC: --dmac 0c:73:eb:92:80:cf"},
			&cli.StringFlag{Name: "protocol", Aliases: []string{"p"}, Usage: "协议: --protocol tcp"},
			&cli.IntFlag{Name: "sport", Usage: "源端口: --sport 22"},
			&cli.IntFlag{Name: "dport", Usage: "目的端口: --dport 22"},
			&cli.StringFlag{Name: "app", Usage: "应用: --app modbus"},
			&cli.StringSliceFlag{Name: "time", Aliases: []string{"t"}, Usage: "时间:--t hour/day/month@16:00:00-18:00:00"},
			&cli.StringFlag{Name: "action", Aliases: []string{"a"}, Usage: "动作: --action accept/drop/log/queue"},
			&cli.StringFlag{Name: "logtag", Aliases: []string{"log"}, Usage: "动作: --logtag log1122"},
			&cli.StringFlag{Name: "policy", Usage: "动作: --policy init"},
		},
		Action: func(cCtx *cli.Context) error {
			// 创建规则
			var policy model.Policy
			sRegion := cCtx.String("sregion")
			if len(sRegion) != 0 {
				regions := strings.Split(sRegion, ",")
				policy.SRegion = regions
			}

			dRegion := cCtx.String("dregion")
			if len(dRegion) != 0 {
				regions := strings.Split(dRegion, ",")
				policy.DRegion = regions
			}

			sIp := cCtx.String("sip")
			if len(sIp) != 0 {
				values := strings.Split(sIp, ",")
				policy.SIp = values
			}

			dIp := cCtx.String("dip")
			if len(dIp) != 0 {
				values := strings.Split(dIp, ",")
				policy.DIp = values
			}

			sMac := cCtx.String("smac")
			if len(sMac) != 0 {
				policy.SMac = sMac
			}

			dMac := cCtx.String("dmac")
			if len(dMac) != 0 {
				policy.DMac = dMac
			}

			protocol := cCtx.String("protocol")
			if len(protocol) != 0 {
				policy.Protocol = protocol
			}

			sport := cCtx.Int("sport")
			if sport != 0 {
				policy.SPort = sport
			}

			dport := cCtx.Int("dport")
			if sport != 0 {
				policy.DPort = dport
			}

			app := cCtx.String("app")
			if len(app) != 0 {
				policy.App = model.App{Name: app}
			}

			// --time day@0-6-9
			timeArray := cCtx.StringSlice("time")
			if len(timeArray) != 0 {
				policy.Time = timeArray
			}

			logTag := cCtx.String("logtag")
			if len(logTag) != 0 {
				policy.LogTag = logTag
			}

			action := cCtx.String("action")
			if len(action) != 0 {
				policy.Action = action
			}

			policyAction := cCtx.String("policy")
			if len(policyAction) != 0 {
				policy.Manager = policyAction
			}

			bs, _ := json.Marshal(policy)
			var out bytes.Buffer
			json.Indent(&out, bs, "", "\t")
			fmt.Printf("policy=%+v\n", out.String())

			managerService := service.PolicyManagerService{}
			err := managerService.GeneratePolicyRule(policy)

			if err != nil {
				return err
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
