package iptools

import (
	"encoding/binary"
	"math"
	"net"
	strerror "netvine.com/firewall/server/utils/error"
	"strings"
)

// GetCidrIpRange 计算ip范围
func GetCidrIpRange(ipStr string) (net.IP, net.IP, error) {
	_, ipNet, err := net.ParseCIDR(ipStr)
	if err != nil {
		return nil, nil, err
	}

	ip := ipNet.IP.To4()
	var min, max uint32
	for i := 0; i < 4; i++ {
		b := uint32(ip[i] & ipNet.Mask[i])
		min += b << ((3 - uint(i)) * 8)
	}
	one, _ := ipNet.Mask.Size()
	max = min | uint32(math.Pow(2, float64(32-one))-1)

	ipStart := make(net.IP, 4)
	ipEnd := make(net.IP, 4)
	binary.BigEndian.PutUint32(ipStart, uint32(min))
	binary.BigEndian.PutUint32(ipEnd, uint32(max))

	return ipStart, ipEnd, nil
}

// GetIpBytes 获取ip地址或者范围
func GetIpBytes(ip string) ([]byte, []byte, error) {
	var startIp []byte
	var endIp []byte

	if strings.Contains(ip, "-") { // 192.168.0.1-192.168.0.255
		ipRange := strings.Split(ip, "-")
		if len(ipRange) < 2 {
			return startIp, endIp, strerror.CreateError("ip range error")
		}
		startIp = net.ParseIP(ipRange[0]).To4()
		endIp = net.ParseIP(ipRange[1]).To4()

	} else if strings.Contains(ip, "/") { // 192.168.0.1/24
		startIpNet, endIpNet, err := GetCidrIpRange(ip)
		if err != nil {
			return nil, nil, err
		}
		startIp = startIpNet.To4()
		endIp = endIpNet.To4()

	} else { // 独立ip地址 192.168.0.1
		startIp = net.ParseIP(ip).To4()
	}
	return startIp, endIp, nil
}
