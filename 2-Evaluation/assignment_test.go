package main

import (
	"math"
	"reflect"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func TestAssignment2(t *testing.T) {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN14QP438)
	kg := ckks.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	rlk := kg.GenRelinearizationKey(sk, 2)

	encoder := ckks.NewEncoder(params)
	pt := encoder.EncodeNew([]float64{1, 2, 3}, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
	ct := ckks.NewEncryptor(params, sk).EncryptNew(pt)

	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})

	t.Run("Pow", func(t *testing.T) {
		ctOut := Pow(evaluator, ct, 3)

		ptOut := ckks.NewDecryptor(params, sk).DecryptNew(ctOut)
		outCmplx := encoder.Decode(ptOut, params.LogSlots())
		out := make([]int, 3)
		for i := range out {
			out[i] = int(math.Round(real(outCmplx[i])))
		}

		if !reflect.DeepEqual(out, []int{1, 8, 27}) {
			t.Fail()
		}
	})

	t.Run("EvalPoly", func(t *testing.T) {
		ctOut := EvalPoly(evaluator, ct, []float64{3, 2, 1}) // 3 + 2*x + x^2

		ptOut := ckks.NewDecryptor(params, sk).DecryptNew(ctOut)
		outCmplx := encoder.Decode(ptOut, params.LogSlots())
		out := make([]int, 3)
		for i := range out {
			out[i] = int(math.Round(real(outCmplx[i])))
		}

		if !reflect.DeepEqual(out, []int{6, 11, 18}) {
			t.Fail()
		}
	})

	t.Run("Average", func(t *testing.T) {
		ctOut := Average(evaluator, ct, 3)

		ptOut := ckks.NewDecryptor(params, sk).DecryptNew(ctOut)
		outCmplx := encoder.Decode(ptOut, params.LogSlots())
		out := int(math.Round(real(outCmplx[0])))

		if out != 2 {
			t.Fail()
		}
	})
}
