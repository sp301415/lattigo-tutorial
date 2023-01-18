package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ckks"
)

func main() {
	// 먼저, 시작하기 전에 파라미터를 정의합니다.
	// 파라미터는 직접 만들거나, 미리 만들어진 ParameterLiteral 값들을 통해 생성할 수 있습니다.
	// PN12QP109 = 12-bit N과 109-bit QP로 이루어진 파라미터
	// 다른 파라미터들도 존재합니다.
	params, _ := ckks.NewParametersFromLiteral(ckks.PN12QP109)

	// 파라미터가 만들어졌다면, 비밀 키와 공개 키를 생성합니다.
	// KeyGenerator를 생성한 뒤, GenSecretKey와 GenPublicKey 메서드를 사용합니다.
	// GenKeyPair 메서드를 사용해도 됩니다.
	keygen := ckks.NewKeyGenerator(params)
	sk := keygen.GenSecretKey()

	// 이제 Lattigo에서 지원하는 여러 구조체들(사실은 인터페이스)을 쓸 수 있습니다.
	// 대표적인 것은 다음과 같습니다:
	//	- KeyGenerator: 키를 생성합니다.
	//	- Encoder: 메시지를 평문으로 인코딩하거나 반대로 디코딩합니다.
	//	- Encryptor: 평문을 암호화합니다.
	//	- Decryptor: 평문을 복호화합니다.
	//	- Evaluator: 암호문에 연산을 적용합니다.

	// 평문을 암호화한 뒤 복호화해봅시다.
	m := []float64{1, 2, 3, 4}

	// 먼저 평문을 메시지로 인코딩합니다.
	// 레벨, 스케일, 슬롯 개수를 인자로 받습니다.
	encoder := ckks.NewEncoder(params)
	pt := encoder.EncodeNew(m, params.MaxLevel(), params.DefaultScale(), params.LogSlots())

	// 암호화합니다.
	encryptor := ckks.NewEncryptor(params, sk)
	ct := encryptor.EncryptNew(pt)

	// 복호화합니다.
	decryptor := ckks.NewDecryptor(params, sk)
	ptOut := decryptor.DecryptNew(ct)

	// 디코딩하고, 결과를 비교해봅시다.
	mOut := encoder.Decode(ptOut, params.LogSlots())[:len(m)]
	fmt.Println(mOut)
}
