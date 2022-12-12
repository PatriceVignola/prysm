package beacon_api

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/prysm/v3/beacon-chain/rpc/apimiddleware"
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
)

func (c *beaconApiValidatorClient) getMultipleValidatorStatus(pubkeys [][]byte, indices []int64) (*ethpb.MultipleValidatorStatusResponse, error) {
	// Build the query string by concatenating the indices and the pubkeys into a comma-separated list
	queryValues := make([]string, len(indices)+len(pubkeys))

	// Append the indices to the query string
	for i, validatorIndex := range indices {
		queryValues[i] = strconv.FormatInt(validatorIndex, 10)
	}

	// Append the public keys to the query string
	for i, pubkey := range pubkeys {
		queryValues[i+len(indices)] = hexutil.Encode(pubkey)
	}

	queryParams := url.Values{}
	queryParams.Add("id", strings.Join(queryValues, ","))
	queryUrl := buildURL("/eth/v1/beacon/states/head/validators", queryParams)

	responseJson := apimiddleware.StateValidatorsResponseJson{}
	_, err := c.jsonRestHandler.GetRestJsonResponse(queryUrl, &responseJson)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get validators state json response")
	}

	validatorStatuses := make([]*ethpb.ValidatorStatusResponse, len(responseJson.Data))
	validatorIndices := make([]types.ValidatorIndex, len(responseJson.Data))
	validatorPubKeys := make([][]byte, len(responseJson.Data))

	for index, responseData := range responseJson.Data {
		validatorIndex, err := strconv.ParseUint(responseData.Index, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse validator index `%s`", responseData.Index)
		}

		pubkey, err := hexutil.Decode(responseData.Validator.PublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode public key `%s`", responseData.Validator.PublicKey)
		}

		validatorIndices[index] = types.ValidatorIndex(validatorIndex)
		validatorPubKeys[index] = pubkey

		activationEpoch, err := strconv.ParseUint(responseData.Validator.ActivationEpoch, 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse activation epoch `%d`", responseData.Validator.ActivationEpoch)
		}

		statusResponse := &ethpb.ValidatorStatusResponse{}
		statusResponse.ActivationEpoch = types.Epoch(activationEpoch)
		statusResponse.Status = beaconAPITogRPCValidatorStatus[responseData.Status]

		isPending := statusResponse.Status == ethpb.ValidatorStatus_DEPOSITED ||
			statusResponse.Status == ethpb.ValidatorStatus_PARTIALLY_DEPOSITED ||
			statusResponse.Status == ethpb.ValidatorStatus_PENDING

		if isPending {
			// Count the number of validators that are ahead of us in the activation queue
			var indexInActivationQueue uint64

			activationQueue, err := c.getActivationQueue()
			if err != nil {
				return nil, errors.Wrap(err, "failed to get activation queue")
			}

			for i, pendingValidatorData := range activationQueue {
				if pendingValidatorData.Index == responseData.Index {
					indexInActivationQueue = uint64(i)
					break
				}
			}

			statusResponse.PositionInActivationQueue = indexInActivationQueue + 1
		}

		validatorStatuses[index] = statusResponse
	}

	response := &ethpb.MultipleValidatorStatusResponse{
		Statuses:   validatorStatuses,
		Indices:    validatorIndices,
		PublicKeys: validatorPubKeys,
	}

	return response, nil
}

// Returns the activation queue in order of activiation eligibility
func (c *beaconApiValidatorClient) getActivationQueue() ([]*apimiddleware.ValidatorContainerJson, error) {
	queryParams := url.Values{}
	queryParams.Add("status", "pending_queued")
	queryUrl := buildURL("/eth/v1/beacon/states/head/validators", queryParams)

	responseJson := apimiddleware.StateValidatorsResponseJson{}
	_, err := c.jsonRestHandler.GetRestJsonResponse(queryUrl, responseJson)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get pending validators state json response")
	}

	// Order the validators by activation eligibility epoch. If 2 validators have the same eligibility epoch, the validator
	// with the lower index gets prioritized.
	sort.Slice(responseJson.Data, func(i, j int) bool {
		myActivationEligibilityEpoch, err := strconv.ParseUint(responseJson.Data[i].Validator.ActivationEligibilityEpoch, 10, 64)
		if err != nil {
			return false
		}

		otherActivationEligibilityEpoch, err := strconv.ParseUint(responseJson.Data[j].Validator.ActivationEligibilityEpoch, 10, 64)
		if err != nil {
			return false
		}

		if myActivationEligibilityEpoch == otherActivationEligibilityEpoch {
			myIndex, err := strconv.ParseUint(responseJson.Data[i].Index, 10, 64)
			if err != nil {
				return false
			}

			otherIndex, err := strconv.ParseUint(responseJson.Data[j].Index, 10, 64)
			if err != nil {
				return false
			}

			return myIndex < otherIndex
		}

		return myActivationEligibilityEpoch < otherActivationEligibilityEpoch
	})

	return responseJson.Data, nil
}

var beaconAPITogRPCValidatorStatus = map[string]ethpb.ValidatorStatus{
	"pending_initialized": ethpb.ValidatorStatus_DEPOSITED,
	"pending_queued":      ethpb.ValidatorStatus_PENDING,
	"active_ongoing":      ethpb.ValidatorStatus_ACTIVE,
	"active_exiting":      ethpb.ValidatorStatus_EXITING,
	"active_slashed":      ethpb.ValidatorStatus_SLASHING,
	"exited_unslashed":    ethpb.ValidatorStatus_EXITED,
	"exited_slashed":      ethpb.ValidatorStatus_EXITED,
	"withdrawal_possible": ethpb.ValidatorStatus_EXITED,
	"withdrawal_done":     ethpb.ValidatorStatus_EXITED,
}
