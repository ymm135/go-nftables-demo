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
