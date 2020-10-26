package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/services/signatures/secp256k1"
	"github.com/smartcontractkit/chainlink/core/services/vrf"
	"github.com/smartcontractkit/chainlink/core/store/models"
	"github.com/smartcontractkit/chainlink/core/store/models/vrfkey"
	"math/big"

	"C"
)

func SeedData(preSeed *big.Int, blockHash common.Hash, blockNum int) (vrf.PreSeedData, error) {
	seedAsSeed, err := vrf.BigToSeed(preSeed)
	if err != nil {
		return vrf.PreSeedData{}, err
	}
	return vrf.PreSeedData{
		PreSeed:   seedAsSeed,
		BlockNum:  uint64(blockNum),
		BlockHash: blockHash,
	}, nil
}

//export GenerateVRFProofString1
func GenerateVRFProofString1(privateKeyInt64 int64, preSeedIn int64, blockHashHexIn *C.char, blockNumIn int) *C.char {
	blocHash := common.BytesToHash(common.Hex2Bytes(C.GoString(blockHashHexIn)))

	value,_ :=GenerateVRFProofString2(privateKeyInt64, preSeedIn, blocHash, blockNumIn)
	return  C.CString(value)
}

func GenerateVRFProofString2(privateKeyInt64 int64, preSeedIn int64, blockHash common.Hash, blockNumIn int) (string, error) {

	preSeedPointer := big.NewInt(preSeedIn)

	s, err := SeedData(preSeedPointer, blockHash, blockNumIn)
	if err != nil {
		return "", err
	}

	bigPrivateKey := big.NewInt(privateKeyInt64)
	if bigPrivateKey.Cmp(secp256k1.GroupOrder) >= 0 || bigPrivateKey.Cmp(big.NewInt(0)) <= 0 {
		return "", fmt.Errorf("secret key must be in {1, ..., #secp256k1 - 1}")
	}
	privateK := secp256k1.IntToScalar(bigPrivateKey)
	suite := secp256k1.NewBlakeKeccackSecp256k1()
	pk, err := suite.Point().Mul(privateK, nil).MarshalBinary()
	if err != nil {
		panic(errors.Wrapf(err, "could not marshal public key"))
	}
	if len(pk) != vrfkey.CompressedPublicKeyLength {
		panic(fmt.Errorf("public key %x has wrong length", pk))
	}

	response, err := vrf.GenerateProofResponse(secp256k1.ScalarToHash(privateK), s)
	if err != nil {
		return "", err
	}

	blockNum := common.BytesToHash(response[vrf.ProofLength : vrf.ProofLength+32]).Big().Uint64()
	proof, err := vrf.UnmarshalSolidityProof(response[:vrf.ProofLength])
	if err != nil {
		return "", errors.Wrap(err, "while parsing ProofResponse")
	}
	preSeed, err := vrf.BigToSeed(proof.Seed)
	if err != nil {
		return "", errors.Wrap(err, "while converting seed to bytes representation")
	}
	p := vrf.ProofResponse{P: proof, PreSeed: preSeed, BlockNum: blockNum}
	rv, err := p.MarshalForVRFCoordinator()
	if err != nil {
		return "", err
	}

	vrfCoordinatorArgs, err := models.VRFFulfillMethod().Inputs.PackValues(
		[]interface{}{
			rv[:], // geth expects slice, even if arg is constant-length
		})
	//if err != nil {
	//	return models.NewRunOutputError(errors.Wrapf(err,
	//		"while packing VRF proof %s as argument to "+
	//			"VRFCoordinator.fulfillRandomnessRequest", solidityProof))
	//}
	if err != nil {
		//TODO.
		return "", err
	}
	return fmt.Sprintf("0x%x", vrfCoordinatorArgs), nil
}

func main() {
	fmt.Print("Main called.")
}
