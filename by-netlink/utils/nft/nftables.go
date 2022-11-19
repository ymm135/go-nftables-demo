package nft

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	iptools "netvine.com/firewall/server/utils"
	"runtime"
	"strings"
	"time"

	strerror "netvine.com/firewall/server/utils/error"

	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

type NfTables struct {
	Conn  *nftables.Conn
	NetNS netns.NsHandle
}

// OpenSystemNFTConn returns a netlink connection that tests against
// the running kernel in a separate network namespace.
// CleanupSystemNFTConn() must be called from a defer to cleanup
// created network namespace.
func OpenSystemNFTConn() (*nftables.Conn, netns.NsHandle) {
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in cleanupSystemNFTConn().
	// runtime.LockOSThread()

	// 使用init进程的namespace
	const init_pid = 1
	ns, err := netns.GetFromPid(init_pid)

	if err != nil {
		fmt.Sprintln("GetFromPid err", err.Error())
	}

	// nftables.AsLasting() 持久连接，可以重用
	// c, err := nftables.New(nftables.WithNetNSFd(int(ns)), nftables.AsLasting())
	c, err := nftables.New(nftables.WithNetNSFd(int(ns)))

	if err != nil {
		fmt.Printf("nftables.New() failed %v \n", err.Error())
	}
	return c, ns
}

func CleanupSystemNFTConn(newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		fmt.Printf("newNS.Close() failed: %v\n", err)
	}
}

func (nft *NfTables) CreateTableIfNotExist(tableName string) (*nftables.Table, error) {
	var table *nftables.Table
	if nft.Conn != nil {
		tables, err := nft.Conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
		if err != nil {
			fmt.Printf("failed to list IPv4 tables: %v\n", err)
			return nil, err
		}

		tableExist := false
		for _, t := range tables {
			if t.Name == tableName {
				tableExist = true
				table = t
				break
			}
		}

		if !tableExist {
			table = nft.Conn.AddTable(&nftables.Table{
				Family: nftables.TableFamilyIPv4,
				Name:   tableName,
			})
		}
	}

	return table, nil
}

func (nft *NfTables) CreateChainIfNotExist(table *nftables.Table, chainName string) (*nftables.Chain, error) {
	var chain *nftables.Chain

	if table == nil {
		return nil, strerror.CreateError("CreateChainIfNotExist nftables 表不能为空")
	}

	if nft.Conn != nil {
		chains, err := nft.Conn.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
		if err != nil {
			fmt.Printf("failed to list IPv4 chains: %v\n", err)
			return nil, err
		}

		chainExist := false
		for _, c := range chains {
			if c.Name == chainName && c.Table.Name == table.Name {
				chainExist = true
				chain = c
				break
			}
		}

		policyDrop := nftables.ChainPolicyDrop
		if !chainExist {
			chain = nft.Conn.AddChain(&nftables.Chain{
				Name:     chainName,
				Table:    table,
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookForward,
				Priority: nftables.ChainPriorityFilter,
				Policy:   &policyDrop,
			})
		}
	}
	return chain, nil
}

// 字符串类型，只要增加一个结束符"\x00"即可
// cmp eq reg 1 0x696c7075 0x00306b6e 0x00000000 0x00000000
// []byte{0x75, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x31, 0x00}
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

// mac地址
func macaddr(addr string) []byte {
	addr = strings.ReplaceAll(addr, ":", "")
	macByte, err := hex.DecodeString(addr)
	if err != nil {
		return macByte
	}
	return macByte
}

// 时间转换
func metaTime(timeStr string) []byte {
	// 1970-01-01
	timeS := "1970-01-01 " + timeStr
	loc, _ := time.LoadLocation("Asia/Shanghai")
	metaTime, err := time.ParseInLocation("2006-01-02 15:04:05", timeS, loc)
	if err != nil {
		return []byte{}
	}

	timestamp := metaTime.Unix()
	bytesBuffer := bytes.NewBuffer([]byte{})
	_ = binary.Write(bytesBuffer, binary.LittleEndian, timestamp)

	byte := bytesBuffer.Bytes()
	return byte[:4]
}

// AddInterfaceExpr 生成网卡规则表达式
func AddInterfaceExpr(table *nftables.Table, conn *nftables.Conn, setName string, key expr.MetaKey, values []string) ([]expr.Any, error) {
	arrLength := len(values)
	var exprLocal []expr.Any

	if arrLength > 0 {
		fmt.Printf("AddInterfaceExpr %v\n", values)

		exprLocal = append(exprLocal, &expr.Meta{Key: key, Register: 1})

		if arrLength <= 1 {
			exprLocal = append(exprLocal, &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(values[0]),
			})
		} else {
			ifSet := &nftables.Set{
				Table:   table,
				Name:    setName,
				KeyType: nftables.TypeIFName,
			}

			var setEle []nftables.SetElement
			for _, name := range values {
				setEle = append(setEle, nftables.SetElement{Key: ifname(name)})
			}

			if err := conn.AddSet(ifSet, setEle); err != nil {
				return nil, strerror.CreateError("AddInterfaceExpr set error")
			}

			exprLocal = append(exprLocal, &expr.Lookup{
				SourceRegister: 1,
				SetName:        ifSet.Name,
				SetID:          ifSet.ID,
			})
		}
	}

	return exprLocal, nil
}

// AddProtocolExpr 生成协议规则表达式 TCP/UDP/ICMP
func AddProtocolExpr(procotolStr string) ([]expr.Any, error) {
	if len(procotolStr) > 0 {
		procotolStr = strings.ToLower(procotolStr)
		protocol := unix.IPPROTO_TCP

		if procotolStr == "udp" {
			protocol = unix.IPPROTO_UDP
		} else if procotolStr == "icmp" {
			protocol = unix.IPPROTO_ICMP
		}

		exprLocal := []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(protocol)},
			},
		}
		return exprLocal, nil
	}
	return nil, nil
}

// AddIPExpr 生成IP规则表达式
func AddIPExpr(table *nftables.Table, conn *nftables.Conn, setName string, payloadOffset uint32, values []string) ([]expr.Any, error) {
	arrLength := len(values)
	var exprLocal []expr.Any

	if arrLength > 0 {
		fmt.Printf("AddIPExpr %v\n", values)

		// [ payload load 4b @ network header + 12 => reg 1 ]
		exprLocal = append(exprLocal, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       payloadOffset, // TODO
			Len:          4,             // TODO
		})

		if arrLength <= 1 {
			startIpByte, endIpByte, err := iptools.GetIpBytes(values[0])
			if err != nil {
				return nil, err
			}

			if len(endIpByte) == 0 {
				// 单个ip
				exprLocal = append(exprLocal, &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     startIpByte,
				})
			} else {
				// ip地址段
				exprLocal = append(exprLocal, &expr.Range{
					Op:       expr.CmpOpEq,
					Register: 1,
					FromData: startIpByte,
					ToData:   endIpByte,
				})
			}
		} else {
			ipSet := &nftables.Set{
				Table:   table,
				Name:    setName,
				KeyType: nftables.TypeIPAddr,
			}

			var setEle []nftables.SetElement
			for _, ipAddr := range values {
				startIpByte, endIpByte, err := iptools.GetIpBytes(ipAddr)
				if err != nil {
					return nil, err
				}
				if len(endIpByte) == 0 {
					setEle = append(setEle, nftables.SetElement{Key: startIpByte})
				} else {
					setEle = append(setEle, nftables.SetElement{Key: startIpByte, KeyEnd: endIpByte})
				}
			}

			if err := conn.AddSet(ipSet, setEle); err != nil {
				return nil, strerror.CreateError("AddInterfaceExpr set error")
			}

			exprLocal = append(exprLocal, &expr.Lookup{
				SourceRegister: 1,
				SetName:        ipSet.Name,
				SetID:          ipSet.ID,
			})
		}
	}

	return exprLocal, nil
}

// GetMacExpr 获取MAC地址规则表达式
func GetMacExpr(metaKey expr.MetaKey, mac string) ([]expr.Any, error) {
	if len(mac) > 0 {
		var offset uint32
		if metaKey == expr.MetaKeyIIFNAME {
			offset = 6
		}

		exprLocal := []expr.Any{
			// meta load iiftype => reg 1
			&expr.Meta{Key: metaKey, Register: 1},
			// cmp eq reg 1 0x00000001
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x01, 0x00},
			},
			// payload load 6b @ link header + 6 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseLLHeader,
				Offset:       offset,
				Len:          6,
			},
			// cmp eq reg 1 0x7a02a4c4 0x00003025
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     macaddr(mac),
			},
		}

		return exprLocal, nil
	}
	return nil, nil
}

// GetPortExpr 获取端口规则表达式
func GetPortExpr(offset uint32, port uint) ([]expr.Any, error) {
	if port > 0 && port <= 65535 {
		hexValue := fmt.Sprintf("%X", port)
		// 确保是4位
		for i := len(hexValue); i < 4; i++ {
			hexValue = "0" + hexValue
		}

		hexByte, _ := hex.DecodeString(hexValue)
		fmt.Printf("%v,%v\n", port, hexByte)

		exprLocal := []expr.Any{
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       offset,
				Len:          2,
			},
			// [ cmp eq reg 1 0x000010e1 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     hexByte,
			},
		}

		return exprLocal, nil
	}
	return nil, nil
}

type TimeType uint

const (
	HourType  TimeType = 0
	DayType   TimeType = 1
	MonthType TimeType = 2

	HourKey  = "hour"
	DayKey   = "day"
	MonthKey = "Month"
)

type PolicyTime struct {
	Type    TimeType
	IsRange bool
	Value   interface{} // 单个值
	Start   interface{} // 范围起始
	End     interface{} // 范围结束
}

// GetTimeExpr 获取时间
// 格式  hour@16:00:00-18:00:00,20:00:00-21:00:00 ; day@1,3-5 ; month@1,20-25
func GetTimeExpr(table *nftables.Table, conn *nftables.Conn, setName string, values []string) ([]expr.Any, error) {
	arrLength := len(values)
	var exprLocal []expr.Any
	var policyRaw []PolicyTime

	if arrLength > 0 {
		fmt.Printf("GetTimeExpr %v\n", values)

		for _, timeVal := range values {
			timeSplit1 := strings.Split(timeVal, "@")
			if len(timeSplit1) < 2 {
				return nil, strerror.CreateError("time type error")
			}

			timeTypeStr := timeSplit1[0]
			timeValArr := strings.Split(timeSplit1[1], ",")

			if len(timeValArr) == 0 {
				return nil, strerror.CreateError("time value error")
			}

			var currTimeType TimeType
			switch timeTypeStr {
			case HourKey:
				currTimeType = HourType
			case DayKey:
				currTimeType = DayType
			case MonthKey:
				currTimeType = MonthType
			}

			for _, val := range timeValArr {
				if strings.Contains(val, "-") {
					timeRangeArr := strings.Split(val, "-")
					if len(timeRangeArr) < 2 {
						return nil, strerror.CreateError("time range error")
					}
					policyRaw = append(policyRaw, PolicyTime{Type: currTimeType, IsRange: true, Start: timeRangeArr[0], End: timeRangeArr[1]})
				} else {
					policyRaw = append(policyRaw, PolicyTime{Type: currTimeType, Value: val})
				}
			}
		}
	}

	return exprLocal, nil
}

// GetLogExpr 获取log规则表达式
func GetLogExpr(logTag string) ([]expr.Any, error) {
	if len(logTag) > 0 {
		// 日志模块
		keyGQ := uint32((1 << unix.NFTA_LOG_PREFIX))
		exprLocal := []expr.Any{&expr.Log{
			Key:        keyGQ,
			QThreshold: uint16(20),
			Group:      uint16(1),
			Snaplen:    uint32(132),
			Data:       []byte(logTag),
		}}
		return exprLocal, nil
	}
	return nil, nil
}

// GetPortExpr 获取端口规则表达式
func GetActionExpr(action string) ([]expr.Any, error) {
	var exprLocal []expr.Any
	if len(action) > 0 {
		var actionExpr expr.VerdictKind

		if action == "drop" {
			actionExpr = expr.VerdictDrop
		} else if action == "accept" {
			actionExpr = expr.VerdictAccept
		} else if action == "log" {
			actionExpr = expr.VerdictAccept
		} else if action == "continue" {
			actionExpr = expr.VerdictContinue
		}

		// 动作
		if action == "queue" {
			exprLocal = append(exprLocal, &expr.Queue{
				Num: 0,
			})
		} else {
			exprLocal = append(exprLocal, &expr.Verdict{
				Kind: actionExpr,
			})
		}
		return exprLocal, nil
	}
	return nil, nil
}
