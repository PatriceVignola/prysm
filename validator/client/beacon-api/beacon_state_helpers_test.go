package beacon_api

import (
	"context"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v4/testing/assert"
	"github.com/prysmaticlabs/prysm/v4/testing/require"
	"github.com/prysmaticlabs/prysm/v4/validator/client/beacon-api/mock"
)

func TestNewBeaconApiMinimalState(t *testing.T) {
	t.Run("correctly handles failures", func(t *testing.T) {
		testCases := []struct {
			name                    string
			jsonSlot                string
			jsonBlockRoots          []string
			jsonFinalizedCheckpoint *apimiddleware.CheckpointJson
			expectedError           string
		}{
			{
				name:          "invalid slot",
				jsonSlot:      "foo",
				expectedError: "failed to parse slot `foo`",
			},
			{
				name:           "invalid block roots",
				jsonSlot:       "1",
				jsonBlockRoots: []string{"bar"},
				expectedError:  "failed to decode block root `bar`",
			},
			{
				name:                    "nil finalized checkpoint",
				jsonSlot:                "1",
				jsonBlockRoots:          []string{hexutil.Encode([]byte{2})},
				jsonFinalizedCheckpoint: nil,
				expectedError:           "finalized checkpoint is nil",
			},
			{
				name:           "invalid finalized epoch",
				jsonSlot:       "1",
				jsonBlockRoots: []string{hexutil.Encode([]byte{2})},
				jsonFinalizedCheckpoint: &apimiddleware.CheckpointJson{
					Epoch: "foo",
				},
				expectedError: "failed to parse finalized epoch `foo`",
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				_, err := newBeaconApiMinimalState(testCase.jsonSlot, testCase.jsonBlockRoots, testCase.jsonFinalizedCheckpoint, 1, "phase0")
				assert.ErrorContains(t, testCase.expectedError, err)
			})
		}
	})

	t.Run("correctly creates minimal state", func(t *testing.T) {
		minimalState, err := newBeaconApiMinimalState(
			"1",
			[]string{
				hexutil.Encode([]byte{2}),
				hexutil.Encode([]byte{3}),
			},
			&apimiddleware.CheckpointJson{Epoch: "4"},
			5,
			"dummy version",
		)
		require.NoError(t, err)

		expectedMinimalState := &beaconApiMinimalState{
			slot: 1,
			blockRoots: [][]byte{
				{2},
				{3},
			},
			finalizedCheckpointEpoch: 4,
			version:                  "dummy version",
			numValidators:            5,
		}

		assert.DeepEqual(t, expectedMinimalState, minimalState)
	})
}

func TestIsActiveAtEpoch(t *testing.T) {
	t.Run("correctly handles failures", func(t *testing.T) {
		testCases := []struct {
			name          string
			jsonValidator *apimiddleware.ValidatorJson
			expectedError string
		}{
			{
				name:          "nil validator",
				jsonValidator: nil,
				expectedError: "validator is nil",
			},
			{
				name: "invalid activation epoch",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "foo",
				},
				expectedError: "failed to parse validator activation epoch `foo`",
			},
			{
				name: "invalid exit epoch",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "1",
					ExitEpoch:       "bar",
				},
				expectedError: "failed to parse validator exit epoch `bar`",
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				_, err := isActiveAtEpoch(testCase.jsonValidator, 1)
				assert.ErrorContains(t, testCase.expectedError, err)
			})
		}
	})

	t.Run("returns the correct result", func(t *testing.T) {
		testCases := []struct {
			name           string
			jsonValidator  *apimiddleware.ValidatorJson
			epoch          primitives.Epoch
			expectedResult bool
		}{
			{
				name: "epoch smaller than activation",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "1",
					ExitEpoch:       "3",
				},
				epoch:          0,
				expectedResult: false,
			},
			{
				name: "epoch same as activation",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "1",
					ExitEpoch:       "3",
				},
				epoch:          1,
				expectedResult: true,
			},
			{
				name: "epoch between activation and exit",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "1",
					ExitEpoch:       "3",
				},
				epoch:          2,
				expectedResult: true,
			},
			{
				name: "epoch same as exit",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "1",
					ExitEpoch:       "3",
				},
				epoch:          3,
				expectedResult: false,
			},
			{
				name: "epoch greater than exit",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "1",
					ExitEpoch:       "3",
				},
				epoch:          4,
				expectedResult: false,
			},
			{
				name: "activation greater than exit",
				jsonValidator: &apimiddleware.ValidatorJson{
					ActivationEpoch: "3",
					ExitEpoch:       "1",
				},
				epoch:          2,
				expectedResult: false,
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				isActive, err := isActiveAtEpoch(testCase.jsonValidator, testCase.epoch)
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedResult, isActive)
			})
		}
	})
}

func TestComputeActiveEffectiveBalanceAtEpoch(t *testing.T) {
	t.Run("correctly handles failures", func(t *testing.T) {
		testCases := []struct {
			name          string
			jsonValidator []*apimiddleware.ValidatorJson
			expectedError string
		}{
			{
				name: "nil validator",
				jsonValidator: []*apimiddleware.ValidatorJson{
					nil,
				},
				expectedError: "validator is nil",
			},
			{
				name: "bad epoch",
				jsonValidator: []*apimiddleware.ValidatorJson{
					{
						ActivationEpoch: "foo",
						ExitEpoch:       "2",
					},
				},
				expectedError: "failed to retrieve whether validator was active at epoch `1`",
			},
			{
				name: "invalid effective balance",
				jsonValidator: []*apimiddleware.ValidatorJson{
					{
						ActivationEpoch:  "1",
						ExitEpoch:        "2",
						EffectiveBalance: "bar",
					},
				},
				expectedError: "failed to parse validator effective balance `bar`",
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				_, err := computeActiveEffectiveBalanceAtEpoch(testCase.jsonValidator, 1)
				assert.ErrorContains(t, testCase.expectedError, err)
			})
		}
	})

	t.Run("returns the correct active effective balance", func(t *testing.T) {
		activeEffectiveBalance, err := computeActiveEffectiveBalanceAtEpoch([]*apimiddleware.ValidatorJson{
			{
				ActivationEpoch:  "1",
				ExitEpoch:        "3",
				EffectiveBalance: "1",
			},
			{
				ActivationEpoch:  "2",
				ExitEpoch:        "5",
				EffectiveBalance: "10",
			},
			{
				ActivationEpoch:  "3",
				ExitEpoch:        "5",
				EffectiveBalance: "100",
			},
			{
				ActivationEpoch:  "4",
				ExitEpoch:        "5",
				EffectiveBalance: "1000",
			},
		}, 3)
		require.NoError(t, err)
		assert.Equal(t, uint64(110), activeEffectiveBalance)
	})
}

func TestAttestedEffectiveBalance(t *testing.T) {
	t.Run("correctly handles failures", func(t *testing.T) {
		testCases := []struct {
			name           string
			jsonValidator  []*apimiddleware.ValidatorJson
			correctlyVoted []bool
			expectedError  string
		}{
			{
				name: "nil validator",
				jsonValidator: []*apimiddleware.ValidatorJson{
					nil,
				},
				expectedError: "validator is nil",
			},
			{
				name: "invalid effective balance",
				jsonValidator: []*apimiddleware.ValidatorJson{
					{
						Slashed:          false,
						EffectiveBalance: "foo",
					},
				},
				correctlyVoted: []bool{true},
				expectedError:  "failed to parse validator effective balance `foo`",
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				_, err := computeAttestedEffectiveBalance(testCase.jsonValidator, testCase.correctlyVoted)
				assert.ErrorContains(t, testCase.expectedError, err)
			})
		}
	})

	t.Run("returns the correct attested effective balance", func(t *testing.T) {
		attestedEffectiveBalance, err := computeAttestedEffectiveBalance([]*apimiddleware.ValidatorJson{
			{
				Slashed:          false,
				EffectiveBalance: "1",
			},
			{
				Slashed:          true,
				EffectiveBalance: "10",
			},
			{
				Slashed:          false,
				EffectiveBalance: "100",
			},
			{
				Slashed:          true,
				EffectiveBalance: "1000",
			},
			{
				Slashed:          false,
				EffectiveBalance: "10000",
			},
		}, []bool{
			true,
			true,
			false,
			false,
			true,
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(10001), attestedEffectiveBalance)
	})
}

func TestGetAttestingIndices(t *testing.T) {
	const committeeEndpoint = "/eth/v1/beacon/states/head/committees?epoch=%d&index=%d&slot=%d"

	t.Run("correctly handles failures", func(t *testing.T) {
		t.Run("nil attestation data", func(t *testing.T) {
			beaconChainClient := beaconApiBeaconChainClient{}
			_, err := beaconChainClient.getAttestingIndices(context.Background(), nil, bitfield.NewBitlist(0))
			assert.ErrorContains(t, "attestation data is nil", err)
		})

		t.Run("bad committee REST request", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			jsonRestHandler := mock.NewMockjsonRestHandler(ctrl)
			jsonRestHandler.EXPECT().GetRestJsonResponse(
				ctx,
				fmt.Sprintf(committeeEndpoint, 0, 1, 2),
				gomock.Any(),
			).Return(
				nil,
				errors.New("foo error"),
			)

			beaconChainClient := beaconApiBeaconChainClient{jsonRestHandler: jsonRestHandler}
			_, err := beaconChainClient.getAttestingIndices(ctx,
				&eth.AttestationData{
					Slot:           2,
					CommitteeIndex: 1,
				},
				bitfield.NewBitlist(0),
			)
			assert.ErrorContains(t, "failed to get committee for committee index `1` and slot `2`", err)
			assert.ErrorContains(t, "foo error", err)
		})

		t.Run("invalid validator index", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			committee := apimiddleware.StateCommitteesResponseJson{}

			jsonRestHandler := mock.NewMockjsonRestHandler(ctrl)
			jsonRestHandler.EXPECT().GetRestJsonResponse(
				ctx,
				fmt.Sprintf(committeeEndpoint, 0, 1, 2),
				&committee,
			).Return(
				nil,
				nil,
			).SetArg(
				2,
				apimiddleware.StateCommitteesResponseJson{
					Data: []*apimiddleware.CommitteeJson{
						{
							Validators: []string{
								"foo",
							},
						},
					},
				},
			)
			beaconChainClient := beaconApiBeaconChainClient{jsonRestHandler: jsonRestHandler}

			bits := bitfield.NewBitlist(1)
			bits.SetBitAt(0, true)

			_, err := beaconChainClient.getAttestingIndices(ctx,
				&eth.AttestationData{
					Slot:           2,
					CommitteeIndex: 1,
				},
				bits,
			)
			assert.ErrorContains(t, "failed to parse validator index `foo`", err)
		})
	})

	t.Run("retrieves the right attesting indices", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.Background()

		committee := apimiddleware.StateCommitteesResponseJson{}

		jsonRestHandler := mock.NewMockjsonRestHandler(ctrl)
		jsonRestHandler.EXPECT().GetRestJsonResponse(
			ctx,
			fmt.Sprintf(committeeEndpoint, 0, 1, 2),
			&committee,
		).Return(
			nil,
			nil,
		).SetArg(
			2,
			apimiddleware.StateCommitteesResponseJson{
				Data: []*apimiddleware.CommitteeJson{
					{
						Validators: []string{
							"1",
							"2",
							"3",
							"4",
							"5",
						},
					},
				},
			},
		)
		beaconChainClient := beaconApiBeaconChainClient{jsonRestHandler: jsonRestHandler}

		bits := bitfield.NewBitlist(5)
		bits.SetBitAt(0, true)
		bits.SetBitAt(1, false)
		bits.SetBitAt(2, true)
		bits.SetBitAt(3, false)
		bits.SetBitAt(4, true)

		attestingIndices, err := beaconChainClient.getAttestingIndices(ctx,
			&eth.AttestationData{
				Slot:           2,
				CommitteeIndex: 1,
			},
			bits,
		)

		expectedAttestingIndices := []primitives.ValidatorIndex{1, 3, 5}

		require.NoError(t, err)
		assert.DeepEqual(t, expectedAttestingIndices, attestingIndices)
	})
}

func TestGetBeaconCommittee(t *testing.T) {
	const committeeEndpoint = "/eth/v1/beacon/states/head/committees?epoch=%d&index=%d&slot=%d"

	t.Run("correctly handles failures", func(t *testing.T) {
		t.Run("bad committee REST request", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			jsonRestHandler := mock.NewMockjsonRestHandler(ctrl)
			jsonRestHandler.EXPECT().GetRestJsonResponse(
				ctx,
				fmt.Sprintf(committeeEndpoint, 0, 1, 2),
				gomock.Any(),
			).Return(
				nil,
				errors.New("foo error"),
			)

			beaconChainClient := beaconApiBeaconChainClient{jsonRestHandler: jsonRestHandler}
			_, err := beaconChainClient.getBeaconCommittee(ctx, 2, 1)
			assert.ErrorContains(t, "failed to query committees for slot `2`", err)
			assert.ErrorContains(t, "foo error", err)
		})

		t.Run("too many committees", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			committee := apimiddleware.StateCommitteesResponseJson{}
			jsonRestHandler := mock.NewMockjsonRestHandler(ctrl)
			jsonRestHandler.EXPECT().GetRestJsonResponse(
				ctx,
				fmt.Sprintf(committeeEndpoint, 0, 1, 2),
				&committee,
			).Return(
				nil,
				nil,
			).SetArg(
				2,
				apimiddleware.StateCommitteesResponseJson{
					Data: []*apimiddleware.CommitteeJson{
						{}, {},
					},
				},
			)

			beaconChainClient := beaconApiBeaconChainClient{jsonRestHandler: jsonRestHandler}
			_, err := beaconChainClient.getBeaconCommittee(ctx, 2, 1)
			assert.ErrorContains(t, "1 committee was expected, but 2 were received", err)
		})

		t.Run("nil committee", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			ctx := context.Background()

			committee := apimiddleware.StateCommitteesResponseJson{}
			jsonRestHandler := mock.NewMockjsonRestHandler(ctrl)
			jsonRestHandler.EXPECT().GetRestJsonResponse(
				ctx,
				fmt.Sprintf(committeeEndpoint, 0, 1, 2),
				&committee,
			).Return(
				nil,
				nil,
			).SetArg(
				2,
				apimiddleware.StateCommitteesResponseJson{
					Data: []*apimiddleware.CommitteeJson{
						nil,
					},
				},
			)

			beaconChainClient := beaconApiBeaconChainClient{jsonRestHandler: jsonRestHandler}
			_, err := beaconChainClient.getBeaconCommittee(ctx, 2, 1)
			assert.ErrorContains(t, "committee data is nil", err)
		})
	})

	t.Run("retrieves the right beacon committee", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.Background()

		committee := apimiddleware.StateCommitteesResponseJson{}

		jsonRestHandler := mock.NewMockjsonRestHandler(ctrl)
		jsonRestHandler.EXPECT().GetRestJsonResponse(
			ctx,
			fmt.Sprintf(committeeEndpoint, 0, 1, 2),
			&committee,
		).Return(
			nil,
			nil,
		).SetArg(
			2,
			apimiddleware.StateCommitteesResponseJson{
				Data: []*apimiddleware.CommitteeJson{
					{
						Validators: []string{
							"1",
							"2",
							"3",
							"4",
							"5",
						},
					},
				},
			},
		)
		beaconChainClient := beaconApiBeaconChainClient{jsonRestHandler: jsonRestHandler}

		beaconCommittee, err := beaconChainClient.getBeaconCommittee(ctx, 2, 1)
		expectedBeaconCommittee := &apimiddleware.CommitteeJson{
			Validators: []string{
				"1",
				"2",
				"3",
				"4",
				"5",
			},
		}

		require.NoError(t, err)
		assert.DeepEqual(t, expectedBeaconCommittee, beaconCommittee)
	})
}

func TestConvertJsonPendingAttestationsToProto(t *testing.T) {
	t.Run("correctly handles failures", func(t *testing.T) {
		t.Run("nil pending attestation", func(t *testing.T) {
			_, err := convertJsonPendingAttestationsToProto([]*apimiddleware.PendingAttestationJson{
				nil,
			})
			assert.ErrorContains(t, "pending attestation is nil", err)
		})
		t.Run("invalid aggregation bits", func(t *testing.T) {
			_, err := convertJsonPendingAttestationsToProto([]*apimiddleware.PendingAttestationJson{
				{
					AggregationBits: "foo",
				},
			})
			assert.ErrorContains(t, "failed to decode aggregation bits `foo`", err)
		})
		t.Run("invalid attestation data", func(t *testing.T) {
			_, err := convertJsonPendingAttestationsToProto([]*apimiddleware.PendingAttestationJson{
				{
					AggregationBits: hexutil.Encode([]byte{1}),
					Data:            nil,
				},
			})
			assert.ErrorContains(t, "failed to convert json attestation data to proto", err)
		})
		t.Run("invalid inclusion delay", func(t *testing.T) {
			_, err := convertJsonPendingAttestationsToProto([]*apimiddleware.PendingAttestationJson{
				{
					AggregationBits: hexutil.Encode([]byte{1}),
					Data: &apimiddleware.AttestationDataJson{
						Slot:            "2",
						CommitteeIndex:  "3",
						BeaconBlockRoot: hexutil.Encode([]byte{4}),
						Source: &apimiddleware.CheckpointJson{
							Epoch: "5",
							Root:  hexutil.Encode([]byte{6}),
						},
						Target: &apimiddleware.CheckpointJson{
							Epoch: "7",
							Root:  hexutil.Encode([]byte{8}),
						},
					},
					InclusionDelay: "bar",
				},
			})
			assert.ErrorContains(t, "failed to parse pending attestation inclusion delay `bar`", err)
		})

		t.Run("invalid proposer index", func(t *testing.T) {
			_, err := convertJsonPendingAttestationsToProto([]*apimiddleware.PendingAttestationJson{
				{
					AggregationBits: hexutil.Encode([]byte{1}),
					Data: &apimiddleware.AttestationDataJson{
						Slot:            "2",
						CommitteeIndex:  "3",
						BeaconBlockRoot: hexutil.Encode([]byte{4}),
						Source: &apimiddleware.CheckpointJson{
							Epoch: "5",
							Root:  hexutil.Encode([]byte{6}),
						},
						Target: &apimiddleware.CheckpointJson{
							Epoch: "7",
							Root:  hexutil.Encode([]byte{8}),
						},
					},
					InclusionDelay: "9",
					ProposerIndex:  "foo",
				},
			})
			assert.ErrorContains(t, "failed to parse pending attestation proposer index `foo`", err)
		})
	})

	t.Run("retrieves the right pending attestations", func(t *testing.T) {
		pendingAttestations, err := convertJsonPendingAttestationsToProto([]*apimiddleware.PendingAttestationJson{
			{
				AggregationBits: hexutil.Encode([]byte{1}),
				Data: &apimiddleware.AttestationDataJson{
					Slot:            "2",
					CommitteeIndex:  "3",
					BeaconBlockRoot: hexutil.Encode([]byte{4}),
					Source: &apimiddleware.CheckpointJson{
						Epoch: "5",
						Root:  hexutil.Encode([]byte{6}),
					},
					Target: &apimiddleware.CheckpointJson{
						Epoch: "7",
						Root:  hexutil.Encode([]byte{8}),
					},
				},
				InclusionDelay: "9",
				ProposerIndex:  "10",
			},
			{
				AggregationBits: hexutil.Encode([]byte{11}),
				Data: &apimiddleware.AttestationDataJson{
					Slot:            "12",
					CommitteeIndex:  "13",
					BeaconBlockRoot: hexutil.Encode([]byte{14}),
					Source: &apimiddleware.CheckpointJson{
						Epoch: "15",
						Root:  hexutil.Encode([]byte{16}),
					},
					Target: &apimiddleware.CheckpointJson{
						Epoch: "17",
						Root:  hexutil.Encode([]byte{18}),
					},
				},
				InclusionDelay: "19",
				ProposerIndex:  "20",
			},
		})

		expectedPendingAttestations := []*ethpb.PendingAttestation{
			{
				AggregationBits: bitfield.Bitlist{1},
				Data: &ethpb.AttestationData{
					Slot:            2,
					CommitteeIndex:  3,
					BeaconBlockRoot: []byte{4},
					Source: &ethpb.Checkpoint{
						Epoch: 5,
						Root:  []byte{6},
					},
					Target: &ethpb.Checkpoint{
						Epoch: 7,
						Root:  []byte{8},
					},
				},
				InclusionDelay: 9,
				ProposerIndex:  10,
			},
			{
				AggregationBits: bitfield.Bitlist{11},
				Data: &ethpb.AttestationData{
					Slot:            12,
					CommitteeIndex:  13,
					BeaconBlockRoot: []byte{14},
					Source: &ethpb.Checkpoint{
						Epoch: 15,
						Root:  []byte{16},
					},
					Target: &ethpb.Checkpoint{
						Epoch: 17,
						Root:  []byte{18},
					},
				},
				InclusionDelay: 19,
				ProposerIndex:  20,
			},
		}

		require.NoError(t, err)
		assert.DeepEqual(t, expectedPendingAttestations, pendingAttestations)
	})
}
