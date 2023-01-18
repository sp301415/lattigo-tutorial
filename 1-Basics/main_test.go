package main

import (
	"reflect"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ckks"
)

func TestAssignment1(t *testing.T) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)
	m := []int{1, 2, 3, 4, 5}

	ct, sk := EncodeAndEncrypt(params, m)
	mOut := DecryptAndDecode(params, sk, ct, len(m))

	if !reflect.DeepEqual(m, mOut) {
		t.Fail()
	}

	// Check if length < 0
	mOut2 := DecryptAndDecode(params, sk, ct, -1)
	if !(reflect.DeepEqual(m, mOut2[:len(m)]) && len(m) == params.Slots()) {
		t.Fail()
	}
}
