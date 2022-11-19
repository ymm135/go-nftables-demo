# go-nftables-demo
go版本的NFT

- [by-netlink](by-netlink/)  直接通过netlink与内核通信，设置规则  
- [by-libnft](by-libnft/) 通过`cgo`调用libnft api，设置规则  

## go-nftable-netlink  
**This is not the correct repository for issues with the Linux nftables project!** This repository contains a third-party Go package to programmatically interact with nftables. Find the official nftables website at https://wiki.nftables.org/  

要生成的规则`rules.nft`
```shell
table ip filter {
	chain FORWARD {
		ether saddr c4:a4:02:7a:25:30 log prefix "accept-log" accept
	}
}
```

netlink调试信息`nft --debug=netlink -f rules.nft`
```
ip (null) (null) use 0
ip filter FORWARD
  [ meta load iiftype => reg 1 ]
  [ cmp eq reg 1 0x00000001 ]
  [ payload load 6b @ link header + 6 => reg 1 ]
  [ cmp eq reg 1 0x7a02a4c4 0x00003025 ]
  [ log prefix accept-log ]
  [ immediate reg 0 accept ]
```


代码:
```go
package main

import (
	"fmt"
	"runtime"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// the running kernel in a separate network namespace.
// cleanupSystemNFTConn() must be called from a defer to cleanup
// created network namespace.
func openSystemNFTConn() (*nftables.Conn, netns.NsHandle) {
	runtime.LockOSThread()

	// init pid
	const init_pid = 1
	ns, err := netns.GetFromPid(init_pid)

	if err != nil {
		fmt.Sprintln("GetFromPid err", err.Error())
	}

	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))

	if err != nil {
		fmt.Sprintln("nftables.New() failed", err.Error())
	}
	return c, ns
}

func cleanupSystemNFTConn(newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		fmt.Printf("newNS.Close() failed: %v", err)
	}
}

func main() {
	c, ns := openSystemNFTConn()
	defer cleanupSystemNFTConn(ns)

	c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	filterChain := c.AddChain(&nftables.Chain{
		Name:     "FORWARD",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	keyGQ := uint32((1 << unix.NFTA_LOG_PREFIX))

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: filterChain,
		Exprs: []expr.Any{
			// meta load iiftype => reg 1
			&expr.Meta{Key: expr.MetaKeyIIFTYPE, Register: 1},
			// cmp eq reg 1 0x00000001
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:      []byte{0x01, 0x00},
			},
			// payload load 6b @ link header + 6 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseLLHeader,
				Offset:       6, // TODO
				Len:          6, // TODO
			},
			// cmp eq reg 1 0x7a02a4c4 0x00003025
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0xc4, 0xa4, 0x02, 0x7a, 0x25, 0x30},
			},
			&expr.Log{
				Key:        keyGQ,
				QThreshold: uint16(20),
				Group:      uint16(1),
				Snaplen:    uint32(132),
				Data:       []byte("accept-log "),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	if err := c.Flush(); err != nil {
		fmt.Println(err.Error())
	}

	rules, err := c.GetRules(filter, filterChain)
	if err != nil {
		fmt.Println("get", err.Error())
	}

	fmt.Printf("rule:%v\n", rules[0])
}
```

## go-nftable-libnft  

安装依赖库
```
apt install libnftables-dev
```

go会把参数封装成`JSON`传给`libnft`  

比如规则文件是
```shell
table ip filter {
	chain FORWARD {
		ether saddr c4:a4:02:7a:25:30 log prefix "accept-log" accept
	}
}
```

`nft -j list ruleset`  
```json
{
    "nftables": [
        {
            "metainfo": {
                "version": "0.9.3", 
                "release_name": "Topsy", 
                "json_schema_version": 1
            }
        }, 
        {
            "table": {
                "family": "ip", 
                "name": "filter", 
                "handle": 7
            }
        }, 
        {
            "chain": {
                "family": "ip", 
                "table": "filter", 
                "name": "FORWARD", 
                "handle": 1
            }
        }, 
        {
            "rule": {
                "family": "ip", 
                "table": "filter", 
                "chain": "FORWARD", 
                "handle": 2, 
                "expr": [
                    {
                        "match": {
                            "op": "==", 
                            "left": {
                                "payload": {
                                    "protocol": "ether", 
                                    "field": "saddr"
                                }
                            }, 
                            "right": "c4:a4:02:7a:25:30"
                        }
                    }, 
                    {
                        "log": {
                            "prefix": "accept-log"
                        }
                    }, 
                    {
                        "accept": null
                    }
                ]
            }
        }
    ]
}
```

源代码[main.go](by-libnft/main.go)   
```shell
package main

import (
	"fmt"

	"github.com/networkplumbing/go-nft/nft"
	nftlib "github.com/networkplumbing/go-nft/nft/lib"
	"github.com/networkplumbing/go-nft/nft/schema"
)

func main() {
	config := nft.NewConfig()
	tableConfig := &schema.Table{
		Name:   "nft-table",
		Family: string(nft.FamilyIP),
	}
	config.AddTable(tableConfig)

	chainConfig := &schema.Chain{
		Table:  tableConfig.Name,
		Family: tableConfig.Family,
		Name:   "nft-chain",
		Type:   schema.TypeFilter,
		Hook:   schema.HookPreRouting,
		Policy: schema.PolicyAccept,
	}

	config.AddChain(chainConfig)

	var exprs []schema.Statement
	ifaceName := "nic0"
	macAddress := "00:00:00:00:00:01"

	exprs = append(exprs, schema.Statement{
		Match: &schema.Match{
			Op:    schema.OperEQ,
			Left:  schema.Expression{RowData: []byte(`{"meta":{"key":"iifname"}}`)},
			Right: schema.Expression{String: &ifaceName},
		},
	})

	exprs = append(exprs, schema.Statement{
		Match: &schema.Match{
			Op:    schema.OperEQ,
			Left:  schema.Expression{RowData: []byte(`{"ether":{"key":"saddr"}}`)},
			Right: schema.Expression{String: &macAddress},
		},
	})

	exprs = append(exprs, schema.Statement{
		Verdict: schema.Accept(),
	})

	ruleConfig := &schema.Rule{
		Family: tableConfig.Family,
		Table:  tableConfig.Name,
		Chain:  chainConfig.Name,
		Expr:   exprs,
	}

	config.AddRule(ruleConfig)

	fmt.Println(nftlib.ApplyConfig(config))
}
```






