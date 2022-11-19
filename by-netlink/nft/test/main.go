package main

import (
	"fmt"
	"netvine.com/firewall/server/model"
	"netvine.com/firewall/server/nft"
)

func main() {
	nftService := nft.PolicyManagerCommandService{}
	var policys []model.Policy

	policy1 := model.Policy{
		SRegion:  []string{"enp2s0"},
		DRegion:  []string{"enp4s0", "enp5s0"},
		SMac:     "32:c8:06:2f:51:5f",
		DMac:     "32:c8:06:2f:51:66",
		SIp:      []string{"192.168.0.1"},
		DIp:      []string{"192.168.0.1", "192.168.1.1-192.168.1.100", "192.168.2.1/24"}, // 四段式子网掩码不支持
		Protocol: "tcp",
		SPort:    20,
		DPort:    30,
		LogTag:   "test-log1",
		Action:   nft.ALLOW,
	}
	policys = append(policys, policy1)

	policy2 := model.Policy{
		SRegion:  []string{"enp2s0"},
		DRegion:  []string{"enp4s0", "enp5s0"},
		SMac:     "32:c8:06:2f:51:5f",
		DMac:     "32:c8:06:2f:51:66",
		SIp:      []string{"192.168.0.1"},
		DIp:      []string{"192.168.0.1", "192.168.1.1-192.168.1.100", "192.168.2.1/24"},
		Protocol: "tcp",
		SPort:    20,
		DPort:    30,
		Time:     []model.PolicyTime{{Hour: "18:00:00-19:00:00", Month: "1,10-15"}},
		LogTag:   "test-log2",
		Action:   nft.ALLOW,
	}
	policys = append(policys, policy2)

	policy3 := model.Policy{
		SRegion:  []string{"enp2s0"},
		DRegion:  []string{"enp4s0", "enp5s0"},
		SMac:     "32:c8:06:2f:51:5f",
		DMac:     "32:c8:06:2f:51:66",
		SIp:      []string{"192.168.0.1"},
		DIp:      []string{"192.168.0.1", "192.168.1.1-192.168.1.100", "192.168.2.1/24"}, // 四段式子网掩码不支持
		Protocol: "tcp",
		SPort:    20,
		DPort:    30,
		Time:     []model.PolicyTime{{Week: "0,1,2,3,4,5,6", Hour: "18:00:00-19:00:00"}},
		LogTag:   "test-log3",
		Action:   nft.ALLOW,
	}
	policys = append(policys, policy3)

	policy4 := model.Policy{
		SRegion:  []string{"enp2s0"},
		DRegion:  []string{"enp4s0", "enp5s0"},
		SMac:     "32:c8:06:2f:51:5f",
		DMac:     "32:c8:06:2f:51:66",
		SIp:      []string{"192.168.0.1"},
		DIp:      []string{"192.168.0.1", "192.168.1.1-192.168.1.100", "192.168.2.1/24"}, // 四段式子网掩码不支持
		Protocol: "tcp",
		SPort:    20,
		DPort:    30,
		Time:     []model.PolicyTime{{Day: "2022-11-22 18:00:00-2022-11-22 19:00:00"}},
		LogTag:   "test-log3",
		Action:   nft.ALLOW,
	}
	policys = append(policys, policy4)

	err := nftService.GeneratePolicyRule(policys)
	if err != nil {
		fmt.Println(err)
		return
	}
}
