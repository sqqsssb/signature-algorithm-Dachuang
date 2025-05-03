package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	bls12381 "github.com/kilic/bls12-381"
)

// ==================== 数据结构定义 ====================
type SmartContract struct {
	contractapi.Contract
}

// 资产结构增强（增加签名相关信息）
type Asset struct {
	ID             string   `json:"ID"`
	Color          string   `json:"Color"`
	Size           int      `json:"Size"`
	Owner          string   `json:"Owner"`
	AppraisedValue int      `json:"AppraisedValue"`
	Algorithm      string   `json:"Algorithm"`  // 使用的签名算法
	PublicKeys     [][]byte `json:"PublicKeys"` // 所有者的公钥列表
	Threshold      int      `json:"Threshold"`  // 多签阈值
}

// 统一签名请求结构
type SignatureRequest struct {
	Algorithm  string   `json:"algorithm"` // 签名算法类型
	Message    []byte   `json:"message"`   // 被签名的原始数据
	S          [][]byte `json:"s"`
	R          [][]byte `json:"r"`
	PublicKeys [][]byte `json:"publicKeys"` // 参与签名的公钥列表
}

// ==================== 资产管理核心逻辑 ====================
// 仅签名的链码函数，返回签名请求的JSON格式
func (s *SmartContract) CreateAssetSign(
	ctx contractapi.TransactionContextInterface,
	id string,
	color string,
	size int,
	owner string,
	appraisedValue int,
	algorithm string,
	threshold int,
) (string, error) {
	// 签名阶段
	sigRequestJSON, err := SignSignature(ctx, owner, id, algorithm)
	if err != nil {
		return "", fmt.Errorf("signature sign failed in CreateAsset TAT: %v", err)
	}

	return string(sigRequestJSON), nil
}

// 仅验证的链码函数，如果验证成功，就把对应的资产写入账本
func (s *SmartContract) CreateAssetVerify(
	ctx contractapi.TransactionContextInterface,
	id string,
	color string,
	size int,
	owner string,
	appraisedValue int,
	algorithm string,
	threshold int,
	sigRequestJSON string,
) error {
	// 验证阶段
	// 解析签名请求
	var sigRequest SignatureRequest
	if err := json.Unmarshal([]byte(sigRequestJSON), &sigRequest); err != nil {
		return fmt.Errorf("invalid signature request format in CreateAsset TAT: %v", err)
	}

	// 验证签名
	valid, err := VerifySignature(ctx, algorithm, sigRequest)
	if err != nil || !valid {
		return fmt.Errorf("signature verification failed in CreateAsset TAT: %v", err)
	}

	// 删除asset存在的判断，允许重复
	/*exists, err := s.AssetExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the asset %s already exists", id)
	}*/

	// 创建资产对象
	asset := Asset{
		ID:             id,
		Color:          color,
		Size:           size,
		Owner:          owner,
		AppraisedValue: appraisedValue,
		Algorithm:      algorithm,
		PublicKeys:     sigRequest.PublicKeys,
		Threshold:      threshold,
	}

	assetJSON, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, assetJSON)
}

func (s *SmartContract) ReadAsset(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %v", err)
	}
	if assetJSON == nil {
		return "", fmt.Errorf("the asset %s does not exist", id)
	}

	return string(assetJSON), nil
}

func (s *SmartContract) AssetExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return assetJSON != nil, nil
}

// ==================== 签名验证核心逻辑 ====================
// 统一验证入口
func VerifySignature(
	ctx contractapi.TransactionContextInterface,
	algorithm string,
	sigRequest SignatureRequest,
) (bool, error) {
	switch algorithm {
	case "ECDSA":
		return VerifyECDSA(sigRequest)
	case "Schnorr":
		return VerifySchnorr(sigRequest)
	case "BLS":
		return VerifyBLS(sigRequest)

	default:
		return false, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// 统一签名入口
func SignSignature(
	ctx contractapi.TransactionContextInterface,
	owner string,
	id string,
	algorithm string,
) ([]byte, error) {
	switch algorithm {
	case "ECDSA":
		return SignECDSA(owner, id, algorithm)
	case "Schnorr":
		return SignSchnorr(owner, id, algorithm)
	case "BLS":
		return SignBLS(owner, id, algorithm)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// ==================== 具体算法实现 ====================
// ====
// ECDSA具体实现
// ====
type PublicKeyJSON struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type fixedReader struct{}

func (f fixedReader) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 42 // 固定字节值
	}
	return len(b), nil
}

func VerifyECDSA(sigRequest SignatureRequest) (bool, error) {
	hash := sha256.Sum256(sigRequest.Message)

	pubKeys := make([]ecdsa.PublicKey, len(sigRequest.PublicKeys))
	for i, pkBytes := range sigRequest.PublicKeys {
		// 解析 DER 格式的公钥
		pubKeyInterface, err := x509.ParsePKIXPublicKey(pkBytes)
		if err != nil {
			return false, fmt.Errorf("x509.ParsePKIXPublicKey to pubKeys failed in VerifyECDSA TAT: %v", err)
		}
		// 确保公钥是 *ecdsa.PublicKey 类型
		pk, ok := pubKeyInterface.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("public key is not of type *ecdsa.PublicKey")
		}
		pubKeys[i] = *pk
	}

	// 一个一个地验证签名
	for i, pubkey_i := range pubKeys {
		r := new(big.Int).SetBytes(sigRequest.R[i])
		s := new(big.Int).SetBytes(sigRequest.S[i])

		// 验证签名
		if !ecdsa.Verify(&pubkey_i, hash[:], r, s) {
			return false, fmt.Errorf("ECDSA signature %d is invalid", i)
		}

	}

	return true, nil
}

func SignECDSA(owner string, id string, algorithm string) ([]byte, error) {
	// 开始根据签名人数生成sigRequestJSON
	signerCount := strings.Count(owner, ",") + 1

	fixedRand := fixedReader{} // 使用自定义的固定 reader

	privKeys := make([]*ecdsa.PrivateKey, signerCount)
	pubKeys := make([]ecdsa.PublicKey, signerCount)
	derBytes := make([][]byte, signerCount)

	// 生成多个签名者
	for i := 0; i < signerCount; i++ {
		privKeys[i], _ = ecdsa.GenerateKey(elliptic.P256(), fixedRand)
		pubKeys[i] = privKeys[i].PublicKey
		derBytes[i], _ = x509.MarshalPKIXPublicKey(&pubKeys[i])
	}

	msg := []byte(owner + "create" + id)
	hash := sha256.Sum256([]byte(msg))

	// 执行签名
	RByte := make([][]byte, signerCount)
	SByte := make([][]byte, signerCount)

	for i, privKeys_i := range privKeys { //遍历每个签名者
		r, s, err := ecdsa.Sign(fixedRand, privKeys_i, hash[:]) // 这里使用固定的随机数源
		if err != nil {
			return nil, fmt.Errorf("failed to sign message: %v", err)
		}

		RByte[i] = r.Bytes()
		SByte[i] = s.Bytes()
	}

	// 构造签名请求
	sigRequestSign := SignatureRequest{
		Algorithm:  algorithm,
		Message:    msg,
		S:          SByte,    // 聚合签名s的字节形式
		R:          RByte,    // 聚合签名r的字节形式
		PublicKeys: derBytes, // 所有参与签名的公钥
	}

	sigRequestJSON, err := json.Marshal(sigRequestSign)
	return sigRequestJSON, err
}

// ====
// Schnorr具体实现
// ====
func VerifySchnorr(sigRequest SignatureRequest) (bool, error) {
	// 获取公钥  byte[]→*secp256k1.PublicKey
	pubKeys := make([]*btcec.PublicKey, len(sigRequest.PublicKeys))
	for i, pkBytes := range sigRequest.PublicKeys {
		pk, err := btcec.ParsePubKey(pkBytes)
		if err != nil {
			return false, fmt.Errorf("sigRequest.PublicKeys to pubKeys failed in VerifySchnorr TAT: %v", err)
		}
		pubKeys[i] = pk
	}

	// 获取签名
	if len(sigRequest.S) != 1 {
		return false, fmt.Errorf("schnorr requires single aggregated signature")
	}
	s := new(big.Int).SetBytes(sigRequest.S[0])

	if len(sigRequest.R) != 1 {
		return false, fmt.Errorf("schnorr requires single aggregated signature")
	}
	R, _ := btcec.ParsePubKey(sigRequest.R[0])

	// 验证签名
	return Verify(pubKeys, sigRequest.Message, R, s), nil
}

func SignSchnorr(owner string, id string, algorithm string) ([]byte, error) {
	// 开始根据签名人数生成sigRequestJSON
	signerCount := strings.Count(owner, ",") + 1

	// 定义切片存储密钥对
	privKeys := make([]*btcec.PrivateKey, signerCount)
	pubKeys := make([]*btcec.PublicKey, signerCount) // pubKeys即是PK
	var pkBytes [][]byte

	// 定义切片存储r_i和R_i
	ris := make([]*btcec.PrivateKey, signerCount)
	Ris := make([]*btcec.PublicKey, signerCount)

	// 生成 n 个密钥对
	for i := 0; i < signerCount; i++ {
		privKeys[i], pubKeys[i] = KeyGen()
		temp := pubKeys[i].SerializeCompressed()
		pkBytes = append(pkBytes, temp)
		ris[i], Ris[i] = KeyGen()
	}

	apk := AggregatePK(pubKeys) // 聚合公钥
	msg := []byte(owner + "create" + id)
	R := AggregateRi(Ris)
	c := H1(apk, R, msg)
	sSign := Sign(privKeys, pubKeys, ris, c)

	// 构造签名请求
	sigRequestSign := SignatureRequest{
		Algorithm:  algorithm,
		Message:    msg,
		S:          [][]byte{sSign.Bytes()},           // 聚合签名s的字节形式
		R:          [][]byte{R.SerializeCompressed()}, // 聚合签名r的字节形式
		PublicKeys: pkBytes,                           // 所有参与签名的公钥
	}

	sigRequestJSON, err := json.Marshal(sigRequestSign)
	return sigRequestJSON, err
}

// btcec.S256() 返回一个 *btcec.KoblitzCurve 对象，表示比特币使用的 secp256k1 曲线
var curve = btcec.S256()

// 生成密钥对
func KeyGen() (*btcec.PrivateKey, *btcec.PublicKey) {
	privateKeyBytes, _ := hex.DecodeString("196f58dcc0499acac06ec90c21eb0e91923c8c189c68a54de406180ced6a1df0")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	return privKey, pubKey // 计算公钥 pk_i = g^{sk_i}（实际上是 pk_i = sk_i · G）
}

// 计算H0哈希
func H0(PK []*btcec.PublicKey, pk *btcec.PublicKey) *big.Int {
	h := sha256.New() // 创建一个 SHA-256 哈希器
	for _, p := range PK {
		h.Write(schnorr.SerializePubKey(p)) // 遍历公钥切片 PK，将每个公钥序列化后写入哈希器
		// schnorr.SerializePubKey(p)：将公钥 p 序列化为字节数组
	}
	h.Write(schnorr.SerializePubKey(pk))
	result := new(big.Int).SetBytes(h.Sum(nil))
	// h.Sum(nil)：计算最终的哈希值（字节数组形式）
	// new(big.Int).SetBytes(...)：将哈希值的字节数组转换为大整数
	result.Mod(result, curve.N) // 模运算
	return result
}

func AggregatePK(PK []*btcec.PublicKey) *btcec.PublicKey {
	apkX, apkY := new(big.Int), new(big.Int) // 存储聚合公钥的坐标  初始值为 (0, 0)，表示椭圆曲线的无穷远点（加法单位元）

	a := make([]*big.Int, len(PK)) // 用于存储每个公钥的权重

	// 计算所有 a_i = H0(PK, pk_i)
	for i, pk := range PK {
		a[i] = H0(PK, pk)
	}

	// 计算聚合公钥：apk = Σ(a_i * PK_i)
	for i, pk := range PK {
		// 获取公钥的坐标（X和Y为 *big.Int）
		pkX := pk.X()
		pkY := pk.Y()

		// 计算标量乘法：a_i * PK_i
		termX, termY := curve.ScalarMult(pkX, pkY, a[i].Bytes())

		// 将结果累加到聚合公钥
		apkX, apkY = curve.Add(apkX, apkY, termX, termY)
	}

	// 将 big.Int 坐标转换为 FieldVal
	var xField, yField btcec.FieldVal
	// SetByteSlice 方法将字节数组设置到 FieldVal 中
	xField.SetByteSlice(apkX.Bytes())
	yField.SetByteSlice(apkY.Bytes())

	// 创建聚合公钥对象
	apk := btcec.NewPublicKey(&xField, &yField)
	return apk
}

// 计算H1哈希
func H1(apk, R *btcec.PublicKey, msg []byte) *big.Int {
	h := sha256.New() // 创建一个 SHA-256 哈希器
	h.Write(schnorr.SerializePubKey(apk))
	h.Write(schnorr.SerializePubKey(R))
	h.Write(msg)
	result := new(big.Int).SetBytes(h.Sum(nil))
	// h.Sum(nil)：计算最终的哈希值（字节数组形式）
	// new(big.Int).SetBytes(...)：将哈希值的字节数组转换为大整数
	result.Mod(result, curve.N) // 模运算
	return result
}

func AggregateRi(Ris []*btcec.PublicKey) *btcec.PublicKey {
	RX, RY := new(big.Int), new(big.Int) // 存储聚合R的坐标  初始值为 (0, 0)，表示椭圆曲线的无穷远点（加法单位元）

	// 计算聚合R：R = Σ(R_i)
	for _, Ri := range Ris {
		// 获取公钥的坐标（X和Y为 *big.Int）
		pkX := Ri.X()
		pkY := Ri.Y()

		// 将结果累加到聚合公钥
		RX, RY = curve.Add(RX, RY, pkX, pkY)
	}

	// 将 big.Int 坐标转换为 FieldVal
	var xField, yField btcec.FieldVal
	// SetByteSlice 方法将字节数组设置到 FieldVal 中
	xField.SetByteSlice(RX.Bytes())
	yField.SetByteSlice(RY.Bytes())

	// 创建聚合公钥对象
	R := btcec.NewPublicKey(&xField, &yField)
	return R
}

// 生成签名（仅计算s部分）
func Sign(privKeys []*btcec.PrivateKey, pubKeys []*btcec.PublicKey, ris []*btcec.PrivateKey, c *big.Int) *big.Int {
	si := new(big.Int)
	s := new(big.Int)
	a := make([]*big.Int, len(pubKeys)) // 用于存储每个公钥的权重
	for i, ri := range ris {
		// 计算a_i
		a[i] = H0(pubKeys, pubKeys[i])
		si.Mul(a[i], privKeys[i].ToECDSA().D)
		si.Mul(si, c)
		si.Add(si, ri.ToECDSA().D)
		si.Mod(si, curve.N)
		s.Add(s, si)
		s.Mod(s, curve.N)
	}
	return s
}

// 验证签名
func Verify(PK []*btcec.PublicKey, msg []byte, R *btcec.PublicKey, s *big.Int) bool {
	apk := AggregatePK(PK)
	c := H1(apk, R, msg)

	// 计算sG
	sGx, sGy := curve.ScalarBaseMult(s.Bytes())

	// 计算R + c*apk
	cApkX, cApkY := curve.ScalarMult(apk.X(), apk.Y(), c.Bytes())
	rightX, rightY := curve.Add(R.X(), R.Y(), cApkX, cApkY)

	return ((sGx.Cmp(rightX) == 0) && (sGy.Cmp(rightY) == 0))
}

// ====
// BLS具体实现
// ====
var bls = bls12381.NewEngine() // 创建一个 bls12-381 椭圆曲线的引擎实例 bls，该引擎提供了在 BLS12 - 381 曲线上进行各种数学运算的功能
var q = bls.G1.Q()             // 获取 G1 群的阶 q

type PrivateKey struct {
	sk *big.Int
}

type PublicKey struct {
	pk *bls12381.PointG2
}

func VerifyBLS(sigRequest SignatureRequest) (bool, error) {
	apk, err := bls.G2.FromBytes(sigRequest.PublicKeys[0])
	if err != nil {
		return false, fmt.Errorf("FromBytes failed in VerifyBLS TAT: %v", err)
	}
	msg := sigRequest.Message
	sigma, err := bls.G1.FromBytes(sigRequest.S[0])
	if err != nil {
		return false, fmt.Errorf("FromBytes failed in VerifyBLS TAT: %v", err)
	}

	return verify(sigma, apk, msg), nil
}

func SignBLS(owner string, id string, algorithm string) ([]byte, error) {
	signerCount := strings.Count(owner, ",") + 1
	msg := []byte(owner + "create" + id)

	var privKeys []*PrivateKey
	var pubKeys []*PublicKey

	var s_is []*bls12381.PointG1

	// 生成密钥对
	for i := 0; i < signerCount; i++ {
		priv, pub, err := KeyGenBLS()
		if err != nil {
			panic(err)
		}
		privKeys = append(privKeys, priv)
		pubKeys = append(pubKeys, pub)
	}

	for i := 0; i < signerCount; i++ {
		s_i := s_i(privKeys[i], pubKeys[i], msg, pubKeys)
		s_is = append(s_is, s_i)
	}

	// 聚合签名
	sigma := aggregateSignatures(s_is)

	// 聚合公钥
	apk := aggregatePublicKeys(pubKeys)

	// 构造签名请求
	sigRequestSign := SignatureRequest{
		Algorithm:  algorithm,
		Message:    msg,
		S:          [][]byte{bls.G1.ToBytes(sigma)}, // 聚合签名s的字节形式
		R:          [][]byte{},                      // 聚合签名r的字节形式
		PublicKeys: [][]byte{bls.G2.ToBytes(apk)},   // 所有参与签名的公钥
	}

	sigRequestJSON, err := json.Marshal(sigRequestSign)
	return sigRequestJSON, err
}

func KeyGenBLS() (*PrivateKey, *PublicKey, error) {
	skbyte, err := hex.DecodeString("3cccf781bb598c94fe9c00275a5c90620bf6f2e89926bf01eae322d8072e9cc4")
	if err != nil {
		return nil, nil, err
	}
	sk := new(big.Int).SetBytes(skbyte)
	// 生成私钥sk_i
	//sk, err := rand.Int(rand.Reader, q) // 使用 rand.Int 函数生成一个小于群阶 q 的随机大整数作为私钥 sk。rand.Reader 是一个安全的随机数生成器，确保生成的随机数具有足够的随机性和不可预测性

	// 计算公钥pk_i = g2^sk_i
	g2 := bls.G2.One() // 获取 G2 群的单位元

	bls.G2.MulScalarBig(g2, g2, sk) // 计算公钥pk_i = g2^sk_i
	pk := &PublicKey{pk: g2}

	return &PrivateKey{sk: sk}, pk, nil
}

// 计算H1(pk_i, {pk_1,...,pk_n}): 返回Z_q的标量a_i
func H1BLS(pk_i *PublicKey, pks []*PublicKey, q *big.Int) *big.Int {
	// 序列化所有公钥
	data := []byte{}          // 初始化一个空的字节切片 data，用于存储所有公钥的序列化结果
	for _, pub := range pks { // 遍历公钥切片 pks
		pkBytes := bls12381.NewG2().ToBytes(pub.pk)
		data = append(data, pkBytes...)
	}
	h := sha256.New() // 创建一个 SHA-256 哈希器
	h.Write(bls12381.NewG2().ToBytes(pk_i.pk))
	h.Write(data)
	result := new(big.Int).SetBytes(h.Sum(nil))
	result.Mod(result, q) // 模运算
	return result
}

// 生成签名s_i = H0(m)^{a_i * sk_i}
func s_i(sk_i *PrivateKey, pk_i *PublicKey, msg []byte, pks []*PublicKey) *bls12381.PointG1 {
	// 计算a_i
	a_i := H1BLS(pk_i, pks, q)

	// 计算a_i * sk_i mod q
	exp := new(big.Int).Mul(a_i, sk_i.sk)
	exp.Mod(exp, q)

	// H0(m)
	h0m, err := bls.G1.HashToCurve(msg, []byte{})
	if err != nil {
		fmt.Printf("Error hashing to curve: %v\n", err)
	}

	// s_i = H0(m) * (a_i * sk_i)
	s_i := bls.G1.New()
	bls.G1.MulScalarBig(s_i, h0m, exp)
	return s_i
}

// 聚合签名σ = s_1 * s_2 * ... * s_n (G1群的加法)
func aggregateSignatures(s_is []*bls12381.PointG1) *bls12381.PointG1 {
	sigma := bls.G1.Zero()
	for _, s := range s_is {
		bls.G1.Add(sigma, sigma, s)
	}
	return sigma
}

// 聚合公钥apk = product (pk_i^{a_i})
func aggregatePublicKeys(pks []*PublicKey) *bls12381.PointG2 {
	apk := bls.G2.Zero()

	for _, pk := range pks {
		a_i := H1BLS(pk, pks, q)
		temp := bls.G2.New()
		bls.G2.MulScalarBig(temp, pk.pk, a_i)
		bls.G2.Add(apk, apk, temp)
	}
	return apk
}

// 验证签名
func verify(sigma *bls12381.PointG1, apk *bls12381.PointG2, msg []byte) bool {
	// 计算 e(σ, g2^{-1})
	g2One := bls.G2.One()
	g2Inv := bls.G2.New()
	bls.G2.Neg(g2Inv, g2One) // g2^{-1} = -g2

	// 添加第一个配对
	bls.AddPair(sigma, g2Inv)

	// 计算 H0(m)
	h0m, err := bls.G1.HashToCurve(msg, []byte{})
	if err != nil {
		fmt.Printf("Error hashing to curve: %v\n", err)
		return false
	}

	// 添加第二个配对
	bls.AddPair(h0m, apk)

	// e(σ, g2^{-1}) * e(H0(m), apk) == 1
	// 计算配对乘积并验证
	gtResult := bls.Result()
	return gtResult.IsOne()
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("Error creating asset chaincode: %v", err)
	}
	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting asset chaincode: %v", err)
	}
}
