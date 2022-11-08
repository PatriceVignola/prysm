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
