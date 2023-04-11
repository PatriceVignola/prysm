package beacon_api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v4/validator/client/iface"
)

type beaconApiBeaconChainClient struct {
	fallbackClient          iface.BeaconChainClient
	jsonRestHandler         jsonRestHandler
	stateValidatorsProvider stateValidatorsProvider
}

func (c beaconApiBeaconChainClient) GetChainHead(ctx context.Context, in *empty.Empty) (*ethpb.ChainHead, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.GetChainHead(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.GetChainHead is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) ListValidatorBalances(ctx context.Context, in *ethpb.ListValidatorBalancesRequest) (*ethpb.ValidatorBalances, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.ListValidatorBalances(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.ListValidatorBalances is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) ListValidators(ctx context.Context, in *ethpb.ListValidatorsRequest) (*ethpb.Validators, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.ListValidators(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.ListValidators is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) GetValidatorQueue(ctx context.Context, in *empty.Empty) (*ethpb.ValidatorQueue, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.GetValidatorQueue(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.GetValidatorQueue is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func (c beaconApiBeaconChainClient) GetValidatorPerformance(ctx context.Context, in *ethpb.ValidatorPerformanceRequest) (*ethpb.ValidatorPerformanceResponse, error) {
	if in.PublicKeys == nil {
		return nil, errors.New("no public keys found")
	}

	const beaconStateEndpoint = "/eth/v2/debug/beacon/states/head"

	type abstractBeaconStateJson struct {
		Version             string          `json:"version" enum:"true"`
		ExecutionOptimistic bool            `json:"execution_optimistic"`
		Data                json.RawMessage `json:"data"`
	}

	// Since we don't know yet what the json looks like, we unmarshal into an abstract structure that has only a version
	// and a blob of data
	beaconStateJson := abstractBeaconStateJson{}
	if _, err := c.jsonRestHandler.GetRestJsonResponse(ctx, beaconStateEndpoint, &beaconStateJson); err != nil {
		return nil, errors.Wrapf(err, "failed to query REST endpoint `%s` (GET)", beaconStateEndpoint)
	}

	// Once we know what the consensus version is, we can go ahead and unmarshal into the specific structs unique to each version
	decoder := json.NewDecoder(bytes.NewReader(beaconStateJson.Data))
	decoder.DisallowUnknownFields()

	pubkeys := make([]string, len(in.PublicKeys))
	for idx, pubkeyBytes := range in.PublicKeys {
		pubkeys[idx] = hexutil.Encode(pubkeyBytes)
	}

	switch beaconStateJson.Version {
	case "phase0":
		phase0BeaconState := apimiddleware.BeaconStateJson{}
		if err := decoder.Decode(&phase0BeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode phase0 beacon state response json")
		}

		return c.getPhase0ValidatorPerformance(
			ctx,
			phase0BeaconState,
			beaconStateJson.Version,
			in.PublicKeys,
		)

	case "altair":
		altairBeaconState := apimiddleware.BeaconStateAltairJson{}
		if err := decoder.Decode(&altairBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode altair beacon state response json")
		}

		minimalAltairJson := minimalBeaconStateAltairJson{
			validators:                 altairBeaconState.Validators,
			balances:                   altairBeaconState.Balances,
			previousEpochParticipation: altairBeaconState.PreviousEpochParticipation,
			slot:                       altairBeaconState.Slot,
			blockRoots:                 altairBeaconState.BlockRoots,
			finalizedCheckpoint:        altairBeaconState.FinalizedCheckpoint,
			inactivityScores:           altairBeaconState.InactivityScores,
		}

		return c.getAltairValidatorPerformance(
			minimalAltairJson,
			beaconStateJson.Version,
			in.PublicKeys,
		)

	case "bellatrix":
		bellatrixBeaconState := apimiddleware.BeaconStateBellatrixJson{}
		if err := decoder.Decode(&bellatrixBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode bellatrix beacon state response json")
		}

		minimalAltairJson := minimalBeaconStateAltairJson{
			validators:                 bellatrixBeaconState.Validators,
			balances:                   bellatrixBeaconState.Balances,
			previousEpochParticipation: bellatrixBeaconState.PreviousEpochParticipation,
			slot:                       bellatrixBeaconState.Slot,
			blockRoots:                 bellatrixBeaconState.BlockRoots,
			finalizedCheckpoint:        bellatrixBeaconState.FinalizedCheckpoint,
			inactivityScores:           bellatrixBeaconState.InactivityScores,
		}

		return c.getAltairValidatorPerformance(
			minimalAltairJson,
			beaconStateJson.Version,
			in.PublicKeys,
		)
	case "capella":
		capellaBeaconState := apimiddleware.BeaconStateCapellaJson{}
		if err := decoder.Decode(&capellaBeaconState); err != nil {
			return nil, errors.Wrap(err, "failed to decode capella beacon state response json")
		}

		minimalAltairJson := minimalBeaconStateAltairJson{
			validators:                 capellaBeaconState.Validators,
			balances:                   capellaBeaconState.Balances,
			previousEpochParticipation: capellaBeaconState.PreviousEpochParticipation,
			slot:                       capellaBeaconState.Slot,
			blockRoots:                 capellaBeaconState.BlockRoots,
			finalizedCheckpoint:        capellaBeaconState.FinalizedCheckpoint,
			inactivityScores:           capellaBeaconState.InactivityScores,
		}

		return c.getAltairValidatorPerformance(
			minimalAltairJson,
			beaconStateJson.Version,
			in.PublicKeys,
		)
	}

	return nil, errors.Errorf("unsupported version `%s` for GetValidatorPerformance()", beaconStateJson.Version)
}

func (c beaconApiBeaconChainClient) GetValidatorParticipation(ctx context.Context, in *ethpb.GetValidatorParticipationRequest) (*ethpb.ValidatorParticipationResponse, error) {
	if c.fallbackClient != nil {
		return c.fallbackClient.GetValidatorParticipation(ctx, in)
	}

	// TODO: Implement me
	panic("beaconApiBeaconChainClient.GetValidatorParticipation is not implemented. To use a fallback client, pass a fallback client as the last argument of NewBeaconApiBeaconChainClientWithFallback.")
}

func NewBeaconApiBeaconChainClientWithFallback(host string, timeout time.Duration, fallbackClient iface.BeaconChainClient) iface.BeaconChainClient {
	jsonRestHandler := beaconApiJsonRestHandler{
		httpClient: http.Client{Timeout: timeout},
		host:       host,
	}

	return &beaconApiBeaconChainClient{
		jsonRestHandler:         jsonRestHandler,
		fallbackClient:          fallbackClient,
		stateValidatorsProvider: beaconApiStateValidatorsProvider{jsonRestHandler: jsonRestHandler},
	}
}
