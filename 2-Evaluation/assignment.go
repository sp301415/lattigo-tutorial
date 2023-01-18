package main

import (
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// Pow returns a new ciphertext encrypting ct^k.
func Pow(evaluator ckks.Evaluator, ct *rlwe.Ciphertext, k int) *rlwe.Ciphertext

// EvalPoly returns a new ciphertext containing the evaluation of polynomial by given coefficients.
// Coefficients are in ascending order; for example,
// {1, 2, 3} means 1 + 2x + 3x^2.
func EvalPoly(evaluator ckks.Evaluator, ct *rlwe.Ciphertext, coeffs []float64) *rlwe.Ciphertext

// Average returns the encrypted average of values packed in ct of given length.
//
// You may assume that evaluator has rotation keys from 1 to length.
func Average(evaluator ckks.Evaluator, ct *rlwe.Ciphertext, length int) *rlwe.Ciphertext

// BONUS QUESTION: Are your implementation optimal?
