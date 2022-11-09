//go:build use_beacon_api
// +build use_beacon_api

package beacon_api

type ErrorResponseJson struct {
	Code    int    `json:"status_code"`
	Message string `json:"message"`
}

type GenesisResponseJson struct {
	Data struct {
		GenesisTime           string `json:"genesis_time" time:"true"`
		GenesisValidatorsRoot string `json:"genesis_validators_root" hex:"true"`
		GenesisForkVersion    string `json:"genesis_fork_version" hex:"true"`
	} `json:"data"`
}

type AttesterDutiesResponseJson struct {
	DependentRoot string `json:"dependent_root" hex:"true"`
	Data          []struct {
		Pubkey                  string `json:"pubkey" hex:"true"`
		ValidatorIndex          string `json:"validator_index"`
		CommitteeIndex          string `json:"committee_index"`
		CommitteeLength         string `json:"committee_length"`
		CommitteesAtSlot        string `json:"committees_at_slot"`
		ValidatorCommitteeIndex string `json:"validator_committee_index"`
		Slot                    string `json:"slot"`
	} `json:"data"`
	ExecutionOptimistic bool `json:"execution_optimistic"`
}

type ProposerDutiesResponseJson struct {
	DependentRoot string `json:"dependent_root" hex:"true"`
	Data          []struct {
		Pubkey         string `json:"pubkey" hex:"true"`
		ValidatorIndex string `json:"validator_index"`
		Slot           string `json:"slot"`
	} `json:"data"`
	ExecutionOptimistic bool `json:"execution_optimistic"`
}

type SyncCommitteeDutiesResponseJson struct {
	Data []struct {
		Pubkey                        string   `json:"pubkey" hex:"true"`
		ValidatorIndex                string   `json:"validator_index"`
		ValidatorSyncCommitteeIndices []string `json:"validator_sync_committee_indices"`
	} `json:"data"`
	ExecutionOptimistic bool `json:"execution_optimistic"`
}

type ValidatorJson struct {
	PublicKey                  string `json:"pubkey" hex:"true"`
	WithdrawalCredentials      string `json:"withdrawal_credentials" hex:"true"`
	EffectiveBalance           string `json:"effective_balance"`
	Slashed                    bool   `json:"slashed"`
	ActivationEligibilityEpoch string `json:"activation_eligibility_epoch"`
	ActivationEpoch            string `json:"activation_epoch"`
	ExitEpoch                  string `json:"exit_epoch"`
	WithdrawableEpoch          string `json:"withdrawable_epoch"`
}

type ValidatorContainerJson struct {
	Index     string         `json:"index"`
	Balance   string         `json:"balance"`
	Status    string         `json:"status" enum:"true"`
	Validator *ValidatorJson `json:"validator"`
}

type StateValidatorsResponseJson struct {
	Data                []*ValidatorContainerJson `json:"data"`
	ExecutionOptimistic bool                      `json:"execution_optimistic"`
}

type StateValidatorResponseJson struct {
	Data                *ValidatorContainerJson `json:"data"`
	ExecutionOptimistic bool                    `json:"execution_optimistic"`
}
