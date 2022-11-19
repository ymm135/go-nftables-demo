package nft

import "netvine.com/firewall/server/model"

type PolicyManagerCommandService struct {
}

func (p *PolicyManagerCommandService) GeneratePolicyRule(policys []model.Policy) error {
	nft := Nft{}
	nft.FlushRuleset()

	err := nft.AddTable(Table{Name: NftTable, AddressFamily: FamilyIP})
	if err != nil {
		return err
	}

	err = nft.AddChain(Chain{Name: BaseRuleChain, Type: TypeFilter, Hook: HookForward, Policy: PolicyAccept})
	if err != nil {
		return err
	}

	for _, p := range policys {
		err := nft.AddRule(p)
		if err != nil {
			return err
		}
	}

	return nil
}
