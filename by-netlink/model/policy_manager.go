package model

type Policy struct {
	Name      string       // 策略名称
	SRegion   []string     // 源区域
	DRegion   []string     // 目的区域
	SIp       []string     // 源IP
	DIp       []string     // 目的ip
	SMac      string       // 源mac地址
	DMac      string       // 目的mac地址
	Protocol  string       // 协议类型 TCP UDP ICMP
	SPort     int          // 源端口
	DPort     int          // 目的端口
	App       App          // 应用
	Action    int          // 动作 0 允许 1 告警 2 阻断
	LogTag    string       // log自定义
	Manager   string       // 策略管理
	Time      []PolicyTime // 时间
	TableName string       // 表明
	ChainName string       // 链名
	LogSwitch int          // 0 关 1 开
}

type App struct {
	Predefine bool   // 是否是预定义的
	Port      int    // 端口号
	Name      string // 协议名
}

type PolicyTime struct {
	Day   string // 日期
	Hour  string // 小时、时间范围
	Week  string // 周
	Month string // 月份
}
