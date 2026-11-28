// Command xitcoin-chain-vectors prints test/fixtures/xitcoin-chain-vectors.json
// using the chain's own Go code: x/bridge/types for the attestation digests and
// MsgSubmitAttestation, the Cosmos SDK for TxBody, AuthInfo, SignDoc and TxRaw,
// and crypto/ethsecp256k1 for the signer key and signature. It never contacts
// a network and uses synthetic small-integer keys only.
//
// It must run inside the evmd module of a pos-chain checkout (which carries
// the SDK replace directives), for example:
//
//	mkdir -p "$POS_CHAIN/evmd/cmd/relayervectors"
//	cp test/reference/xitcoin-chain-vectors/main.go "$POS_CHAIN/evmd/cmd/relayervectors/"
//	(cd "$POS_CHAIN/evmd" && go run ./cmd/relayervectors "$(git rev-parse HEAD)") > vectors.json
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	sdkmath "cosmossdk.io/math"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/xitcoin-xtc/pos-chain/crypto/ethsecp256k1"
	bridgetypes "github.com/xitcoin-xtc/pos-chain/x/bridge/types"
)

const (
	chainID = "xitcoin-testnet-v2-1"
	// The route ID stored by the bridge module on xitcoin-testnet-v2-1.
	routeID = "0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9"
)

func key(n int64) *ecdsa.PrivateKey {
	k, err := crypto.ToECDSA(common32(big.NewInt(n)))
	must(err)
	return k
}

func common32(n *big.Int) []byte {
	out := make([]byte, 32)
	n.FillBytes(out)
	return out
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

func account(k *ecdsa.PrivateKey) string {
	address, err := bech32.ConvertAndEncode("xtc", crypto.PubkeyToAddress(k.PublicKey).Bytes())
	must(err)
	return address
}

type attestationVector struct {
	RouteID            string   `json:"routeId"`
	Direction          string   `json:"direction"`
	SourceChainID      string   `json:"sourceChainId"`
	SourceRef          string   `json:"sourceRef"`
	Nonce              string   `json:"nonce"`
	Destination        string   `json:"destination"`
	Amount             string   `json:"amount"`
	DeadlineUnix       string   `json:"deadlineUnix"`
	AttestationID      string   `json:"attestationId"`
	PayloadHash        string   `json:"payloadHash"`
	SigningDigest      string   `json:"signingDigest"`
	ApproverKeys       []int64  `json:"approverKeyNumbers"`
	ApprovalSignatures []string `json:"approvalSignatures"`
}

type transactionVector struct {
	Name           string `json:"name"`
	SubmitterKey   int64  `json:"submitterKeyNumber"`
	Submitter      string `json:"submitter"`
	AccountNumber  string `json:"accountNumber"`
	Sequence       string `json:"sequence"`
	GasLimit       string `json:"gasLimit"`
	FeeAmount      string `json:"feeAmount"`
	Message        string `json:"message"`
	TxBody         string `json:"txBody"`
	TxSignerAndFee string `json:"txSignerAndFee"`
	SignDoc        string `json:"signDoc"`
	SigningDigest  string `json:"signingDigest"`
	Signature      string `json:"signature"`
	TxRaw          string `json:"txRaw"`
	TxHash         string `json:"txHash"`
	SimulateQuery  string `json:"simulateRequest"`
}

type output struct {
	Comment      string              `json:"comment"`
	PosChain     string              `json:"posChainCommit"`
	ChainID      string              `json:"chainId"`
	Attestation  attestationVector   `json:"attestation"`
	Transactions []transactionVector `json:"transactions"`
}

func main() {
	if len(os.Args) != 2 || len(os.Args[1]) != 40 {
		fmt.Fprintln(os.Stderr, "usage: relayervectors <pos-chain commit>")
		os.Exit(2)
	}
	sdk.GetConfig().SetBech32PrefixForAccount("xtc", "xtcpub")
	attestation := bridgetypes.Attestation{
		RouteID:       routeID,
		Direction:     bridgetypes.DirectionCronosToXitcoin,
		SourceChainID: "338",
		SourceRef:     "0x" + hex.EncodeToString(sha256Bytes("relayer vector deposit")),
		Nonce:         18,
		Destination:   account(key(0x200)),
		Amount:        "1250000000000000000",
		DeadlineUnix:  1999999999,
	}
	id, err := attestation.ID()
	must(err)
	payloadHash, err := attestation.PayloadHash(chainID)
	must(err)
	digest, err := bridgetypes.SigningDigest(attestation, chainID)
	must(err)
	// Approvals as the relayer signers return them: V is 27 or 28, ordered by
	// recovered address (key 2 then key 1). The chain accepts both V forms.
	approvers := []int64{2, 1}
	signatures := make([][]byte, 0, len(approvers))
	encoded := make([]string, 0, len(approvers))
	for _, n := range approvers {
		signature, err := crypto.Sign(digest.Bytes(), key(n))
		must(err)
		signature[64] += 27
		signatures = append(signatures, signature)
		encoded = append(encoded, hx(signature))
	}
	signers := make([]string, 0, 3)
	for _, n := range []int64{1, 2, 3} {
		signers = append(signers, crypto.PubkeyToAddress(key(n).PublicKey).Hex())
	}
	recovered, err := bridgetypes.VerifyApprovals(attestation, chainID, signers, signatures)
	must(err)
	if len(recovered) != 2 {
		panic("approvals not verified")
	}

	out := output{
		Comment:  "Generated by test/reference/xitcoin-chain-vectors/main.go from the pinned pos-chain commit; synthetic small-integer keys only.",
		PosChain: os.Args[1],
		ChainID:  chainID,
		Attestation: attestationVector{
			RouteID: attestation.RouteID, Direction: string(attestation.Direction), SourceChainID: attestation.SourceChainID,
			SourceRef: attestation.SourceRef, Nonce: fmt.Sprint(attestation.Nonce), Destination: attestation.Destination,
			Amount: attestation.Amount, DeadlineUnix: fmt.Sprint(attestation.DeadlineUnix),
			AttestationID: hx(id[:]), PayloadHash: hx(payloadHash[:]), SigningDigest: digest.Hex(),
			ApproverKeys: approvers, ApprovalSignatures: encoded,
		},
	}
	for _, c := range []struct {
		name                    string
		submitterKey            int64
		accountNumber, sequence uint64
		gasLimit                uint64
		fee                     int64
	}{
		{"first transaction of a fresh account (defaults omitted)", 0x100, 0, 0, 250000, 450000000000000},
		{"later transaction", 0x101, 12, 7, 263421, 526842000000000},
	} {
		out.Transactions = append(out.Transactions, transaction(c.name, c.submitterKey, c.accountNumber, c.sequence, c.gasLimit, c.fee, attestation, signatures))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(out))
}

func sha256Bytes(text string) []byte {
	sum := sha256.Sum256([]byte(text))
	return sum[:]
}

func transaction(name string, submitterKey int64, accountNumber, sequence, gasLimit uint64, fee int64,
	attestation bridgetypes.Attestation, signatures [][]byte) transactionVector {
	private := key(submitterKey)
	signer := &ethsecp256k1.PrivKey{Key: crypto.FromECDSA(private)}
	submitter := account(private)
	msg := &bridgetypes.MsgSubmitAttestation{
		Submitter: submitter, RouteId: attestation.RouteID, Direction: string(attestation.Direction),
		SourceChainId: attestation.SourceChainID, SourceRef: attestation.SourceRef, Nonce: attestation.Nonce,
		Destination: attestation.Destination, Amount: attestation.Amount, DeadlineUnix: attestation.DeadlineUnix,
		Signatures: signatures,
	}
	must(msg.ValidateBasic())
	message, err := msg.Marshal()
	must(err)
	msgAny, err := codectypes.NewAnyWithValue(msg)
	must(err)
	body := &txtypes.TxBody{Messages: []*codectypes.Any{msgAny}}
	bodyBytes, err := body.Marshal()
	must(err)
	pubAny, err := codectypes.NewAnyWithValue(signer.PubKey())
	must(err)
	authInfo := &txtypes.AuthInfo{
		SignerInfos: []*txtypes.SignerInfo{{
			PublicKey: pubAny,
			ModeInfo:  &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Single_{Single: &txtypes.ModeInfo_Single{Mode: signingtypes.SignMode_SIGN_MODE_DIRECT}}},
			Sequence:  sequence,
		}},
		Fee: &txtypes.Fee{Amount: sdk.NewCoins(sdk.NewCoin("axtc", sdkmath.NewInt(fee))), GasLimit: gasLimit},
	}
	authInfoBytes, err := authInfo.Marshal()
	must(err)
	signDoc := &txtypes.SignDoc{BodyBytes: bodyBytes, AuthInfoBytes: authInfoBytes, ChainId: chainID, AccountNumber: accountNumber}
	signDocBytes, err := signDoc.Marshal()
	must(err)
	signature, err := signer.Sign(signDocBytes)
	must(err)
	if !signer.PubKey().VerifySignature(signDocBytes, signature) {
		panic("signature does not verify")
	}
	raw := &txtypes.TxRaw{BodyBytes: bodyBytes, AuthInfoBytes: authInfoBytes, Signatures: [][]byte{signature}}
	rawBytes, err := raw.Marshal()
	must(err)
	hash := sha256.Sum256(rawBytes)
	simulate := &txtypes.SimulateRequest{TxBytes: rawBytes}
	simulateBytes, err := simulate.Marshal()
	must(err)
	return transactionVector{
		Name: name, SubmitterKey: submitterKey, Submitter: submitter,
		AccountNumber: fmt.Sprint(accountNumber), Sequence: fmt.Sprint(sequence), GasLimit: fmt.Sprint(gasLimit), FeeAmount: fmt.Sprint(fee),
		Message: hx(message), TxBody: hx(bodyBytes), TxSignerAndFee: hx(authInfoBytes), SignDoc: hx(signDocBytes),
		SigningDigest: hx(crypto.Keccak256(signDocBytes)), Signature: hx(signature), TxRaw: hx(rawBytes), TxHash: hx(hash[:]),
		SimulateQuery: hx(simulateBytes),
	}
}
