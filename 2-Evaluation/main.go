package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func main() {
	params, _ := ckks.NewParametersFromLiteral(ckks.PN13QP218)

	keygen := ckks.NewKeyGenerator(params)
	sk := keygen.GenSecretKey()

	encoder := ckks.NewEncoder(params)
	pt0 := encoder.EncodeNew([]float64{1, 3, 5, 7}, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
	pt1 := encoder.EncodeNew([]float64{2, 4, 6, 8}, params.MaxLevel(), params.DefaultScale(), params.LogSlots())

	encryptor := ckks.NewEncryptor(params, sk)
	ct0 := encryptor.EncryptNew(pt0)
	ct1 := encryptor.EncryptNew(pt1)

	// Evaluation Key들을 만듭니다.
	// Relinearization Key와 Rotation Key가 있습니다.
	rlk := keygen.GenRelinearizationKey(sk, 1)                            // s^2 -> s이므로, maxDegree = 1
	rtks := keygen.GenRotationKeysForRotations([]int{1, 2, 3}, false, sk) // 1, 2, 3 rotation에 대한 키 생성

	// Evaluator를 만듭니다.
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rtks})

	// (ct0 * (ct0 + ct1)) <<< 1을 계산하는 예제
	ctRes := evaluator.AddNew(ct0, ct1)

	evaluator.Mul(ctRes, ct0, ctRes)
	evaluator.Relinearize(ctRes, ctRes) // MulRelin도 있음
	evaluator.Rescale(ctRes, params.DefaultScale(), ctRes)

	evaluator.Rotate(ctRes, 1, ctRes)

	// 복호화 후 출력
	decryptor := ckks.NewDecryptor(params, sk)
	ptRes := decryptor.DecryptNew(ctRes)
	fmt.Println(encoder.Decode(ptRes, params.LogSlots())[:4])
}
