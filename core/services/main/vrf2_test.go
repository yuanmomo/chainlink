package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"testing"
)



func TestVRF_GenerateVRFProofString(t *testing.T) {
	var sk = 0xdeadbeefdeadbee
	blockHash := common.Hash{}
	blockNum := 0
	preSeed := int64(1)

	proofString,err := GenerateVRFProofString2(int64(sk),preSeed,blockHash,blockNum);
	require.NoError(t, err)

	fmt.Print(proofString)
}

