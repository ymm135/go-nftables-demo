package nft

import (
	"fmt"
	"log"
	"netvine.com/firewall/server/model"
	strerror "netvine.com/firewall/server/utils/error"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	NftTable            = "netvine-table"
	BaseRuleChain       = "base-rule-chain"
	IpMacBlackListChain = "ip-mac-blacklist-chain"
	IpMacBindingChain   = "ip-mac-binding-chain"
)

type NFTCommand string

const (
	AddTable     NFTCommand = "nft add table %s %s"
	AddChain     NFTCommand = "nft add chain %s %s %s {type %s hook %s priority filter\\; policy %s\\; }" // nft add chain ip {tableName} {chainName}
	FlushRuleSet NFTCommand = "nft flush ruleset"
	AddRule      NFTCommand = "nft add rule %s %s %s %s"
)

type ChainType string
type ChainHook string
type ChainPolicy string
type RuleAction string

// Chain Types
const (
	TypeFilter ChainType = "filter"
	TypeNAT    ChainType = "nat"
	TypeRoute  ChainType = "route"
)

// Chain Hooks
const (
	HookPreRouting  ChainHook = "HookPreRouting"
	HookInput       ChainHook = "HookInput"
	HookOutput      ChainHook = "HookOutput"
	HookForward     ChainHook = "forward"
	HookPostRouting ChainHook = "HookPostRouting"
	HookIngress     ChainHook = "HookIngress"
)

// Chain Policies
const (
	PolicyAccept ChainPolicy = "accept"
	PolicyDrop   ChainPolicy = "drop"
	PolicyQueue  ChainPolicy = "queue"
)

const (
	ALLOW int = 0
	WARN  int = 1
	DROP  int = 2
)

// Rule Action
const (
	ActionAccept RuleAction = "accept"
	ActionDrop   RuleAction = "drop"  // 阻断
	ActionQueue  RuleAction = "queue" // 允许 // 告警
)

type AddressFamily string

// Address Families
const (
	FamilyIP     AddressFamily = "ip"
	FamilyIP6    AddressFamily = "ip6"
	FamilyINET   AddressFamily = "inet"
	FamilyARP    AddressFamily = "arp"
	FamilyBridge AddressFamily = "bridge"
	FamilyNETDEV AddressFamily = "netdev"
)

type Table struct {
	Name          string
	AddressFamily AddressFamily
}

type Chain struct {
	Name   string
	Type   ChainType
	Hook   ChainHook
	Policy ChainPolicy
}

type MetaType string

const (
	mark_str    = "\\\""
	mark        = "\""
	gap         = " "
	comma       = ","
	value_range = "-"
)

const (
	MetaIIfName    MetaType = "iifname"      // 入接口
	MetaOfName     MetaType = "oifname"      // 出接口
	MetaIPSAddr    MetaType = "ip saddr"     // 源IP
	MetaIPDAddr    MetaType = "ip daddr"     // 目的IP
	MetaEtherSAddr MetaType = "ether saddr"  // 源MAC
	MetaEtherDAddr MetaType = "ether daddr"  // 目的MAC
	MetaIPProtocol MetaType = "meta l4proto" // 协议
	MetaIpSPort    MetaType = "th sport"     // 源端口
	MetaIpDPort    MetaType = "th dport"     // 目的端口
	MetaTimeHour   MetaType = "meta hour"    // 小时 meta hour "09:00:00"-"10:00:00"
	MetaTimeDay    MetaType = "meta day"     // 星期 meta day [0-6]
	MetaTimeStamp  MetaType = "meta time"    //meta time "2022-06-06 00:00:00"-"2022-06-06 23:00:00"
	MetaLogPrefix  MetaType = "log prefix"
	MetaEmpty      MetaType = ""
)

type Nft struct {
	Table Table
	Chain Chain
}

func (c *Nft) AddTable(table Table) error {
	command := fmt.Sprintf(string(AddTable), table.AddressFamily, table.Name)
	err := c.Exec(command)
	if err == nil {
		c.Table = table
	}

	return err
}

func (c *Nft) AddChain(chain Chain) error {
	var emptyTable Table
	if c.Table == emptyTable {
		return strerror.CreateError("table not exist!")
	}

	command := fmt.Sprintf(string(AddChain), c.Table.AddressFamily, c.Table.Name, chain.Name, chain.Type, chain.Hook, chain.Policy)
	err := c.Exec(command)
	if err == nil {
		c.Chain = chain
	}

	return err
}

func (c *Nft) AddRule(policy model.Policy) error {
	var exprs string
	var err error
	// 出入接口
	if len(policy.SRegion) != 0 {
		expr, err := AddExpr(MetaIIfName, policy.SRegion)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// 出入接口
	if len(policy.DRegion) != 0 {
		expr, err := AddExpr(MetaOfName, policy.DRegion)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// 源IP
	if len(policy.SIp) != 0 {
		expr, err := AddExpr(MetaIPSAddr, policy.SIp)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// 目的IP
	if len(policy.DIp) != 0 {
		expr, err := AddExpr(MetaIPDAddr, policy.DIp)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// 协议
	if len(policy.Protocol) != 0 {
		expr, err := AddSingleExpr(MetaIPProtocol, policy.Protocol)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// source mac
	if len(policy.SMac) != 0 {
		expr, err := AddSingleExpr(MetaEtherSAddr, policy.SMac)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// dest mac
	if len(policy.DMac) != 0 {
		expr, err := AddSingleExpr(MetaEtherDAddr, policy.DMac)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// source prot
	if policy.SPort != 0 {
		expr, err := AddSingleExpr(MetaIpSPort, strconv.FormatInt(int64(policy.SPort), 10))
		if err != nil {
			return err
		}
		exprs += expr
	}

	//dest port
	if policy.DPort != 0 {
		expr, err := AddSingleExpr(MetaIpDPort, strconv.FormatInt(int64(policy.DPort), 10))
		if err != nil {
			return err
		}
		exprs += expr
	}

	// 时间
	if len(policy.Time) != 0 {
		expr, err := getTimePolicyExpr(policy.Time)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// 日志
	// 特征值^#W@L   warn字段表示告警，也就是命中后告警
	if len(policy.LogTag) != 0 {
		if policy.Action == WARN { // 告警动作，命中规则需要告警，记录到告警表中
			policy.LogTag += "#W"
		}

		if policy.LogSwitch == 1 { // 日志开关，命中规则需要展示详细信息，存储到系统安全日志
			policy.LogTag += "@L"
		}

		expr, err := AddSingleExpr(MetaLogPrefix, policy.LogTag)
		if err != nil {
			return err
		}
		exprs += expr
	}

	// 动作
	var action RuleAction
	switch policy.Action {
	case ALLOW:
		fallthrough
	case WARN:
		action = ActionQueue
	case DROP:
		action = ActionDrop
	}

	expr, err := AddSingleExpr(MetaEmpty, string(action))
	if err != nil {
		return err
	}
	exprs += expr

	command := fmt.Sprintf(string(AddRule), c.Table.AddressFamily, c.Table.Name, c.Chain.Name, exprs)
	err = c.Exec(command)

	return err
}

func AddSingleExpr(metaType MetaType, value string) (string, error) {
	length := len(value)
	var expr string
	if length == 0 {
		return "", nil
	}

	expr = string(metaType) + gap + value + gap
	return expr, nil
}

func AddExpr(metaType MetaType, values []string) (string, error) {
	length := len(values)
	var expr string
	if length == 0 {
		return "", nil
	}

	expr = string(metaType) + gap
	if length == 1 {
		expr += values[0]
	} else {
		expr += AddSet(values)
	}
	expr += gap
	return expr, nil
}

func AddStrExpr(metaType MetaType, values []string) (string, error) {
	length := len(values)
	var expr string
	if length == 0 {
		return "", nil
	}

	expr = string(metaType) + gap
	if length == 1 {
		value := values[0]
		if strings.Contains(value, value_range) {

			rangeArr := strings.Split(value, value_range)
			if len(rangeArr) != 2 && len(rangeArr) != 6 {
				return "", strerror.CreateError("AddStrExpr error:" + value)
			}
			if len(rangeArr) == 2 {
				expr += mark_str + rangeArr[0] + mark_str + value_range + mark_str + rangeArr[1] + mark_str
			} else {
				// 2022-11-22 18:00:00-2022-11-22 19:00:00
				thirdRange := 3
				count := 0
				rangeIndex := -1
				for i := 0; i < len(value); i++ {
					if value[i] == '-' {
						count += 1
						if count == thirdRange {
							rangeIndex = i
							break
						}
					}
				}
				if rangeIndex != -1 {
					expr += mark_str + value[:rangeIndex] + mark_str + value_range + mark_str + value[rangeIndex+1:] + mark_str
				} else {
					return "", strerror.CreateError("AddStrExpr parse error:" + value)
				}
			}
		} else {
			expr += mark_str + values[0] + mark_str
		}

	} else {
		expr += AddStrSet(values)
	}
	expr += gap
	return expr, nil
}

func AddSet(elements []string) string {
	var expr string
	if len(elements) != 0 {
		expr += "{ "
		for _, e := range elements {
			expr += mark + e + mark + comma + gap
		}
		expr += "}"
	}
	return expr
}

func AddStrSet(elements []string) string {
	var expr string
	if len(elements) != 0 {
		expr += "{ "
		for _, e := range elements {
			expr += mark_str + e + mark_str + comma + gap
		}
		expr += "}"
	}
	return expr
}

func (c *Nft) FlushRuleset() {
	c.Exec(string(FlushRuleSet))
}

func (c *Nft) Exec(command string) error {
	cmd := exec.Command("/bin/bash", "-c", command)
	err := cmd.Run()

	fmt.Println(cmd.String())

	if err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", err)
		return err
	}
	return nil
}

func getTimePolicyExpr(times []model.PolicyTime) (string, error) {
	var exprs string
	var err error

	for _, policyTime := range times {
		// 日期时间，时间戳
		if len(policyTime.Day) != 0 {
			expr, err := AddStrExpr(MetaTimeStamp, []string{policyTime.Day})
			if err != nil {
				return "", err
			}
			exprs += expr
		}

		// 小时
		if len(policyTime.Hour) != 0 && len(policyTime.Month) == 0 {
			expr, err := AddStrExpr(MetaTimeHour, []string{policyTime.Hour})
			if err != nil {
				return "", err
			}
			exprs += expr
		}

		// 周
		if len(policyTime.Week) != 0 {
			expr, err := AddSingleExpr(MetaTimeDay, "{ "+policyTime.Week+" }")
			if err != nil {
				return "", err
			}
			exprs += expr
		}

		// 月
		if len(policyTime.Month) != 0 {
			monthExprs, err := GetMonthExprs(policyTime.Month, policyTime.Hour)
			if err != nil {
				return "", err
			}
			exprs += monthExprs
		}
	}

	return exprs, err
}

// GetMonthExprs 解析月份 1,2,3,4-23
func GetMonthExprs(monthDaysStr string, hour string) (string, error) {
	monthDays := strings.Split(monthDaysStr, comma)
	var startHour, endHour string
	var timeRange []string

	if len(hour) != 0 {
		hourRange := strings.Split(hour, value_range)
		if len(hourRange) != 2 {
			fmt.Println("hour value error:", hour)
		} else {
			startHour = hourRange[0]
			endHour = hourRange[1]
		}
	}
	for _, days := range monthDays {
		if strings.Contains(days, value_range) { // 持续时间
			daysRange := strings.Split(days, value_range)
			if len(daysRange) != 2 {
				return "", strerror.CreateError("day range error:" + days)
			}
			startDay, err := strconv.Atoi(daysRange[0])
			if err != nil {
				return "", err
			}
			endDay, err := strconv.Atoi(daysRange[1])
			if err != nil {
				return "", err
			}

			for day := startDay; day <= endDay; day++ {
				month, err := GetTimeDayFromMonth(day, startHour, endHour)
				if err != nil {
					return "", err
				}
				timeRange = append(timeRange, month...)
			}
		} else { // 单个时间
			dayInt, err := strconv.Atoi(days)
			if err != nil {
				return "", err
			}

			month, err := GetTimeDayFromMonth(dayInt, startHour, endHour)
			if err != nil {
				return "", err
			}
			timeRange = append(timeRange, month...)
		}
	}

	expr, err := AddStrExpr(MetaTimeStamp, timeRange)
	return expr, err
}

func GetTimeDayFromMonth(targetDay int, startHour string, endHour string) ([]string, error) {
	now := time.Now()
	day := now.Day()
	var timeRange []string
	var startDate, endDate time.Time
	var startDateStr, endDateStr string

	// 当月第一天
	currMonthFirstDate := now.AddDate(0, 0, -day+targetDay)
	currDate := currMonthFirstDate.Format("2006-01-02")
	if len(startHour) == 0 {
		startDateStr = currDate + gap + "00:00:00"
		endDateStr = currDate + gap + "23:59:59"
	} else {
		startDateStr = currDate + gap + startHour
		endDateStr = currDate + gap + endHour
	}
	loc, _ := time.LoadLocation("Local")
	startDate, err := time.ParseInLocation("2006-01-02 15:04:05", startDateStr, loc)
	if err != nil {
		return nil, err
	}

	endDate, err = time.ParseInLocation("2006-01-02 15:04:05", endDateStr, loc)
	if err != nil {
		return nil, err
	}

	// 找出一年的日期
	for i := 0; i < 12; i++ {
		startDateStr = startDate.AddDate(0, i, 0).Format("2006-01-02 15:04:05")
		endDateStr = endDate.AddDate(0, i, 0).Format("2006-01-02 15:04:05")

		timeRange = append(timeRange, startDateStr+mark_str+value_range+mark_str+endDateStr)
	}
	return timeRange, err
}
