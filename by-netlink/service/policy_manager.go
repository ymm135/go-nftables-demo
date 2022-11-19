package service

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"netvine.com/firewall/server/model"
	"netvine.com/firewall/server/utils/nft"
	"strings"
	"time"
)

const (
	tableName = "filter"
	chainName = "FORWARD"

	NFT_META_TIME_NS   = 30
	NFT_META_TIME_DAY  = 31
	NFT_META_TIME_HOUR = 32
)

type PolicyManagerService struct {
	Nft   *nft.NfTables
	Table *nftables.Table
	Chain *nftables.Chain
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

func (p *PolicyManagerService) InitNft(flushrule bool) (err error) {

	if p.Nft == nil {
		conn, nsHandle := nft.OpenSystemNFTConn()
		p.Nft = &nft.NfTables{Conn: conn, NetNS: nsHandle}
	}

	if p.Nft != nil {

		if flushrule {
			// TODO
			// 设置之前清理所有规则
			p.Nft.Conn.FlushRuleset()
			if err := p.Nft.Conn.Flush(); err != nil {
				fmt.Printf("FlushRuleset Flush() failed: %v\n", err)
			}
		}

		p.Table, err = p.Nft.CreateTableIfNotExist(tableName)
		if err != nil {
			return err
		}

		p.Chain, err = p.Nft.CreateChainIfNotExist(p.Table, chainName)
		if err != nil {
			return err
		}

		if err := p.Nft.Conn.Flush(); err != nil {
			fmt.Printf("InitNft Flush() failed: %v\n", err)
		}
	}
	return nil
}

func (p *PolicyManagerService) GeneratePolicyRule(policy model.Policy) error {

	flushruleset := (policy.Manager == "init")
	err := p.InitNft(flushruleset)
	if err != nil {
		fmt.Printf("GeneratePolicyRule Error %v", err)
	}

	var exprs []expr.Any

	// 入接口
	ifExpr, err := nft.AddInterfaceExpr(p.Table, p.Nft.Conn, "if_set", expr.MetaKeyIIFNAME, policy.SRegion)
	if err != nil {
		return err
	}
	if len(ifExpr) != 0 {
		exprs = append(exprs, ifExpr...)
	}

	// 出接口
	ofExpr, err := nft.AddInterfaceExpr(p.Table, p.Nft.Conn, "of_set", expr.MetaKeyOIFNAME, policy.SRegion)
	if err != nil {
		return err
	}
	if len(ofExpr) != 0 {
		exprs = append(exprs, ofExpr...)
	}

	// 协议
	protocolExpr, err := nft.AddProtocolExpr(policy.Protocol)
	if err != nil {
		return err
	}
	if len(protocolExpr) != 0 {
		exprs = append(exprs, protocolExpr...)
	}

	// 源IP
	sourceIpExpr, err := nft.AddIPExpr(p.Table, p.Nft.Conn, "sip_set", 12, policy.SIp)
	if err != nil {
		return err
	}
	if len(sourceIpExpr) != 0 {
		exprs = append(exprs, sourceIpExpr...)
	}

	// 目的IP
	destIpExpr, err := nft.AddIPExpr(p.Table, p.Nft.Conn, "dip_set", 16, policy.DIp)
	if err != nil {
		return err
	}
	if len(destIpExpr) != 0 {
		exprs = append(exprs, destIpExpr...)
	}

	// source mac addr
	sourceMacExpr, err := nft.GetMacExpr(expr.MetaKeyIIFTYPE, policy.SMac)
	if err != nil {
		return err
	}
	if len(sourceMacExpr) != 0 {
		exprs = append(exprs, sourceMacExpr...)
	}

	//dst mac
	destMacExpr, err := nft.GetMacExpr(expr.MetaKeyOIFTYPE, policy.DMac)
	if err != nil {
		return err
	}
	if len(destMacExpr) != 0 {
		exprs = append(exprs, destMacExpr...)
	}

	// 源端口
	sourcePortExpr, err := nft.GetPortExpr(0, uint(policy.SPort))
	if err != nil {
		return err
	}
	if len(sourcePortExpr) != 0 {
		exprs = append(exprs, sourcePortExpr...)
	}

	// 目的端口
	destPortExpr, err := nft.GetPortExpr(2, uint(policy.DPort))
	if err != nil {
		return err
	}
	if len(destPortExpr) != 0 {
		exprs = append(exprs, destPortExpr...)
	}

	// 时间
	timeExpr, err := nft.GetTimeExpr(p.Table, p.Nft.Conn, "time_set", policy.Time)
	if err != nil {
		return err
	}
	if len(timeExpr) != 0 {
		exprs = append(exprs, timeExpr...)
	}

	// 日志
	logExpr, err := nft.GetLogExpr(policy.LogTag)
	if err != nil {
		return err
	}
	if len(logExpr) != 0 {
		exprs = append(exprs, logExpr...)
	}

	// 动作
	actionExpr, err := nft.GetActionExpr(policy.Action)
	if err != nil {
		return err
	}
	if len(actionExpr) != 0 {
		exprs = append(exprs, actionExpr...)
	}

	if len(exprs) > 0 {
		rule := &nftables.Rule{Table: p.Table, Chain: p.Chain, Exprs: exprs}
		p.Nft.Conn.AddRule(rule)
	}

	if err := p.Nft.Conn.Flush(); err != nil {
		fmt.Printf("%v", err)
		return err
	}

	return nil
}
