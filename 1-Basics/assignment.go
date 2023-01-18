package main

import (
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// EncodeAndEncrypt does the following:
//
//   - It creates the secret key using params given,
//   - Then encodes & encrypts the given integer slice,
//   - And finally returns the secret key and ciphertext.
//
// While encoding, use the max level, default scale, and full slots.
func EncodeAndEncrypt(params ckks.Parameters, values []int) (*rlwe.Ciphertext, *rlwe.SecretKey)

// DecryptAndDecode does the following:
//
//   - It decodes & decrypts the given ciphertext using secret key,
//   - then returns the value with given length. If length < 0, then it returns the full slice.
//
// While decoding, assume that ciphertext used the max level, default scale, and full slots.
func DecryptAndDecode(params ckks.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, length int) []int
