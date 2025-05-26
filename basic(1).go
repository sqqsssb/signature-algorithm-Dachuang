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
	"time"

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
	case "PIXEL":
		return VerifyPixel(sigRequest)
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
	case "PIXEL":
		return SignPixel(owner, id, algorithm)
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

// pixel签名方案
const (
	c       = 256          // 哈希输出长度
	l       = 3            // 二叉树层数(根为1层)
	maxTime = (1 << l) - 1 // 最大时刻2^l-1
)

// 系统参数
type SystemParams struct {
	q        *big.Int
	g1       *bls12381.PointG1
	g2       *bls12381.PointG2
	hBase    *bls12381.PointG1   // 独立参数 h
	hList    []*bls12381.PointG1 // h0~hl
	timeTree *TimeNode
}

var params SystemParams
var t int

// 时刻节点
type TimeNode struct {
	Path  string
	Time  int
	Left  *TimeNode
	Right *TimeNode
}

// 私钥组件
type SecretKeyComponent struct {
	c *bls12381.PointG2
	d *bls12381.PointG1
	e []*bls12381.PointG1
}

// 私钥
type SecretKey struct {
	Components  map[string]SecretKeyComponent
	CurrentTime int
}

// 公钥(与BLS算法定义相同，不再重新定义)
/*type PublicKey struct {
	pk *bls12381.PointG2
}*/

// 签名
type Signature struct {
	q1 *bls12381.PointG1
	q2 *bls12381.PointG2
}

var blsEngine = bls12381.NewEngine()

// 生成固定的标量值
func fixedScalar() *big.Int {
	// 由于数值可能超出 int64 范围，使用 SetString 方法初始化
	value, ok := new(big.Int).SetString("495251780521057351040282298935360735053720702066949362454810189783500262403131", 10)
	if !ok {
		panic("Failed to parse big integer")
	}
	return value
}

func Setup() (*SystemParams, error) {
	// 获取BLS12-381曲线参数
	q := blsEngine.G1.Q() // 群阶

	// 初始化生成元
	g1 := blsEngine.G1.One()
	g2 := blsEngine.G2.One()

	// 生成随机参数h_base和h_list
	hBase := blsEngine.G1.New()
	blsEngine.G1.MulScalarBig(hBase, g1, fixedScalar())

	hList := make([]*bls12381.PointG1, l+1)
	for i := range hList {
		h := blsEngine.G1.New()
		blsEngine.G1.MulScalarBig(h, g1, fixedScalar())
		hList[i] = h
	}

	// 构建时间树
	timeTree := buildTimeTree(l)

	return &SystemParams{
		q:        q,
		g1:       g1,
		g2:       g2,
		hBase:    hBase,
		hList:    hList,
		timeTree: timeTree,
	}, nil
}

// 构建时刻树（与之前相同）
func buildTimeTree(layers int) *TimeNode {
	counter := 0
	var preOrder func(*TimeNode, string, int) *TimeNode
	preOrder = func(node *TimeNode, path string, depth int) *TimeNode {
		if depth >= layers {
			return nil
		}
		counter++
		node = &TimeNode{Path: path, Time: counter}
		node.Left = preOrder(nil, path+"1", depth+1)
		node.Right = preOrder(nil, path+"2", depth+1)
		return node
	}
	return preOrder(nil, "", 0)
}

// 密钥生成
func KeyGenPixel() (*SecretKey, *PublicKey, error) {
	x := fixedScalar()
	pk := blsEngine.G2.New()
	blsEngine.G2.MulScalarBig(pk, params.g2, x)

	initialPath := getPathByTime(params.timeTree, 1)
	r := fixedScalar()

	// 计算c = g2^r
	c := blsEngine.G2.New()
	blsEngine.G2.MulScalarBig(c, params.g2, r)

	// 计算d = h^x * h0^r
	dPart1 := blsEngine.G1.New()
	blsEngine.G1.MulScalarBig(dPart1, params.hBase, x)
	dPart2 := blsEngine.G1.New()
	blsEngine.G1.MulScalarBig(dPart2, params.hList[0], r)
	d := blsEngine.G1.New()
	blsEngine.G1.Add(d, dPart1, dPart2)

	// 生成e切片
	e := make([]*bls12381.PointG1, l)
	for i := 0; i < l; i++ {
		elem := blsEngine.G1.New()
		blsEngine.G1.MulScalarBig(elem, params.hList[i+1], r)
		e[i] = elem
	}

	skComponent := SecretKeyComponent{
		c: c,
		d: d,
		e: e,
	}

	return &SecretKey{
			Components:  map[string]SecretKeyComponent{initialPath: skComponent},
			CurrentTime: 1,
		},
		&PublicKey{pk: pk},
		nil
}

// 公钥聚合算法

func KeyAg(pks []*PublicKey) (*PublicKey, error) {

	if len(pks) == 0 {
		return nil, fmt.Errorf("no public keys to aggregate")

	}
	aggregatedPk := blsEngine.G2.New()
	aggregatedPk.Set(pks[0].pk)
	for i := 1; i < len(pks); i++ {
		blsEngine.G2.Add(aggregatedPk, aggregatedPk, pks[i].pk)
	}
	return &PublicKey{pk: aggregatedPk}, nil
}

// 签名函数
func SignInPixel(sk *SecretKey, msg []byte) (*Signature, error) {
	currentPath := getPathByTime(params.timeTree, sk.CurrentTime)
	k := len(currentPath)
	comp, exists := sk.Components[currentPath]
	if !exists {
		return nil, fmt.Errorf("component missing")
	}

	// 解析时间路径
	tj := make([]int, k)
	for i := 0; i < k; i++ {
		switch currentPath[i] {
		case '1':
			tj[i] = 1
		case '2':
			tj[i] = 2
		default:
			return nil, fmt.Errorf("invalid path")
		}
	}

	H0 := hashMsg(msg, params.q)
	rPrime := fixedScalar()

	// 计算q1 = d + e_l*H0(m) + (h0 + Σh_j*tj + h_l*H0(m)) * rPrime
	q1 := blsEngine.G1.New()
	q1.Set(comp.d)
	// 添加e_l*H0(m)
	eLast := comp.e[len(comp.e)-1]
	temp := blsEngine.G1.New()
	blsEngine.G1.MulScalarBig(temp, eLast, H0)
	blsEngine.G1.Add(q1, q1, temp)

	// 计算hSum = h0 + Σh_j*tj + h_l*H0(m)
	hSum := blsEngine.G1.New()
	hSum.Set(params.hList[0])
	for j := 1; j <= k; j++ {
		term := blsEngine.G1.New()
		blsEngine.G1.MulScalarBig(term, params.hList[j], big.NewInt(int64(tj[j-1])))
		blsEngine.G1.Add(hSum, hSum, term)
	}

	// 添加h_l*H0(m)
	hLTerm := blsEngine.G1.New()
	blsEngine.G1.MulScalarBig(hLTerm, params.hList[l], H0)
	blsEngine.G1.Add(hSum, hSum, hLTerm)

	// 乘以rPrime并添加到q1
	hSumR := blsEngine.G1.New()
	blsEngine.G1.MulScalarBig(hSumR, hSum, rPrime)
	blsEngine.G1.Add(q1, q1, hSumR)

	// 计算q2 = c + g2^rPrime
	q2 := blsEngine.G2.New()
	q2.Set(comp.c)
	g2R := blsEngine.G2.New()
	blsEngine.G2.MulScalarBig(g2R, params.g2, rPrime)
	blsEngine.G2.Add(q2, q2, g2R)

	return &Signature{q1: q1, q2: q2}, nil
}

// 签名聚合算法

func SignAg(signatures []*Signature) (*Signature, error) {

	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signatures to aggregate")
	}

	aggregatedQ1 := blsEngine.G1.New()
	aggregatedQ1.Set(signatures[0].q1)
	aggregatedQ2 := blsEngine.G2.New()
	aggregatedQ2.Set(signatures[0].q2)

	for i := 1; i < len(signatures); i++ {
		blsEngine.G1.Add(aggregatedQ1, aggregatedQ1, signatures[i].q1)
		blsEngine.G2.Add(aggregatedQ2, aggregatedQ2, signatures[i].q2)
	}
	return &Signature{q1: aggregatedQ1, q2: aggregatedQ2}, nil
}

func UpdateKey(sk *SecretKey) error {
	currentPath := getPathByTime(params.timeTree, sk.CurrentTime)
	currentTime := sk.CurrentTime

	if len(currentPath) < l-1 {
		// 生成 t||1 的私钥组件
		skComponent := sk.Components[currentPath]

		// 计算新d = d + e[0]
		newD := blsEngine.G1.New()
		blsEngine.G1.Add(newD, skComponent.d, skComponent.e[0])

		newE := make([]*bls12381.PointG1, len(skComponent.e[1:]))
		for i, point := range skComponent.e[1:] {
			newPoint := blsEngine.G1.New()
			newPoint.Set(point)
			newE[i] = newPoint
		}
		newSkComponent1 := SecretKeyComponent{
			c: skComponent.c,
			d: newD,
			e: newE,
		}

		// 生成 t||2 的私钥组件
		rPrime := fixedScalar()
		nextPath2 := currentPath + "2"
		kPrime := len(nextPath2)
		k := len(currentPath)
		if k >= kPrime {
			return fmt.Errorf("invalid prefix length")
		}

		// 解析路径位
		wj := make([]int, kPrime)
		for i := 0; i < kPrime; i++ {
			switch nextPath2[i] {
			case '1':
				wj[i] = 1
			case '2':
				wj[i] = 2
			default:
				return fmt.Errorf("invalid character in wPrime")
			}
		}

		// --- 计算c' = c + g2^rPrime ---
		g2Prime := blsEngine.G2.New()
		blsEngine.G2.MulScalarBig(g2Prime, params.g2, rPrime)
		cPrime := blsEngine.G2.New()
		blsEngine.G2.Add(cPrime, skComponent.c, g2Prime)

		// --- 计算d' = d + Σ(w_j*e_j) + (h0 + Σ(w_j*h_j)) * rPrime ---
		// 计算Σ(w_j*e_j) j=k到kPrime-1
		prodTerm := blsEngine.G1.New()
		for j := k; j < kPrime; j++ {
			term := blsEngine.G1.New()
			blsEngine.G1.MulScalarBig(term, skComponent.e[j-k], big.NewInt(int64(wj[j])))
			blsEngine.G1.Add(prodTerm, prodTerm, term)
		}

		// 计算hSum = h0 + Σ(w_j*h_j)
		hSum := blsEngine.G1.New()
		hSum.Set(params.hList[0]) //h0
		for j := 0; j < kPrime; j++ {
			term := blsEngine.G1.New()
			blsEngine.G1.MulScalarBig(term, params.hList[j+1], big.NewInt(int64(wj[j])))
			blsEngine.G1.Add(hSum, hSum, term)
		}

		// 计算hTerm = hSum * rPrime
		hTerm := blsEngine.G1.New()
		blsEngine.G1.MulScalarBig(hTerm, hSum, rPrime)

		// 合并d'
		dPrime := blsEngine.G1.New()
		blsEngine.G1.Add(dPrime, skComponent.d, prodTerm)
		blsEngine.G1.Add(dPrime, dPrime, hTerm)

		// --- 更新e列表 e_i' = e_i + h_i*rPrime ---
		newE = make([]*bls12381.PointG1, len(skComponent.e)-(kPrime-k))
		copy(newE, skComponent.e[(kPrime-k):])

		for j := 0; j < len(newE); j++ {
			term := blsEngine.G1.New()
			blsEngine.G1.MulScalarBig(term, params.hList[kPrime+1+j], rPrime)
			blsEngine.G1.Add(newE[j], newE[j], term)
		}

		newSkComponent2 := SecretKeyComponent{
			c: cPrime,
			d: dPrime,
			e: newE,
		}

		// 更新私钥组件
		delete(sk.Components, currentPath)
		sk.Components[currentPath+"1"] = newSkComponent1
		sk.Components[currentPath+"2"] = newSkComponent2

		sk.CurrentTime = currentTime + 1
	} else if len(currentPath) == (l - 1) {
		delete(sk.Components, currentPath)
		sk.CurrentTime = currentTime + 1
	} else {
		return fmt.Errorf("invalid path length")
	}

	return nil
}

// 聚合签名验证算法
func VerifyAg(apk *PublicKey, sig *Signature, msg []byte, t int) bool {
	currentPath := getPathByTime(params.timeTree, t)
	k := len(currentPath)
	tj := make([]int, k)
	for i := 0; i < k; i++ {
		switch currentPath[i] {
		case '1':
			tj[i] = 1
		case '2':
			tj[i] = 2
		default:
			return false
		}
	}

	H := hashMsg(msg, params.q)
	// 构建C = h0 + Σh_j*tj + h_l*H(M)
	C := blsEngine.G1.New()
	C.Set(params.hList[0])
	for i := 0; i < k; i++ {
		term := blsEngine.G1.New()
		blsEngine.G1.MulScalarBig(term, params.hList[i+1], big.NewInt(int64(tj[i])))
		blsEngine.G1.Add(C, C, term)
	}

	hLTerm := blsEngine.G1.New()
	blsEngine.G1.MulScalarBig(hLTerm, params.hList[l], H)
	blsEngine.G1.Add(C, C, hLTerm)

	// 计算配对

	blsEngine.Reset()
	blsEngine.AddPair(sig.q1, params.g2)
	left := blsEngine.Result()
	blsEngine.Reset()
	blsEngine.AddPair(params.hBase, apk.pk)
	blsEngine.AddPair(C, sig.q2)
	right := blsEngine.Result()
	return left.Equal(right)
}

// 辅助函数保持不变
func getPathByTime(root *TimeNode, t int) string {
	var search func(*TimeNode) string
	result := ""
	search = func(n *TimeNode) string {
		if n == nil || result != "" {
			return ""
		}
		if n.Time == t {
			result = n.Path
			return result
		}
		// 递归调用 search 函数
		leftResult := search(n.Left)
		if leftResult != "" {
			return leftResult
		}
		rightResult := search(n.Right)
		if rightResult != "" {
			return rightResult
		}
		return ""
	}
	search(root)
	return result
}
func hashMsg(msg []byte, q *big.Int) *big.Int {
	// 计算消息的 SHA-256 哈希值
	h := sha256.Sum256(msg)
	// 将哈希结果转换为 big.Int 类型
	hashInt := new(big.Int).SetBytes(h[:])
	// 对哈希结果取模 q，确保结果在 [0, q-1] 范围内
	return new(big.Int).Mod(hashInt, q)
}

// 周期性调用函数的 goroutine
func periodicCall(sks []*SecretKey) (string, error) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for i, sk := range sks {
				// 更新密钥
				if err := UpdateKey(sk); err != nil {
					return "", fmt.Errorf("UpdateKey failed for signer %d: %v", i, err)
				}
			}
		}
	}
}

func SignPixel(owner string, id string, algorithm string) ([]byte, error) {
	// 初始化系统参数
	t = 1
	signerCount := strings.Count(owner, ",") + 1
	message := []byte(owner + "create" + id)

	params1, err := Setup()
	if err != nil {
		panic(err)
	}
	params = *params1
	// 生成多个私钥和公钥
	var sks []*SecretKey
	var pks []*PublicKey
	for i := 0; i < signerCount; i++ {
		sk, pk, err := KeyGenPixel()
		if err != nil {
			panic(err)
		}
		sks = append(sks, sk)
		pks = append(pks, pk)
	}
	// 对消息进行签名
	var sigs []*Signature
	for _, sk := range sks {
		sig, err := SignInPixel(sk, []byte(message))
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, sig)

	}

	go periodicCall(sks) //周期调用更新私钥
	// 聚合公钥
	apk, err := KeyAg(pks)
	if err != nil {
		panic(err)
	}
	// 聚合签名
	aggregatedSig, err := SignAg(sigs)
	if err != nil {
		panic(err)
	}
	// 构造签名请求
	sigRequestSign := SignatureRequest{
		Algorithm:  algorithm,
		Message:    message,
		S:          [][]byte{bls.G1.ToBytes(aggregatedSig.q1)}, // 聚合签名s的字节形式
		R:          [][]byte{bls.G2.ToBytes(aggregatedSig.q2)}, // 聚合签名r的字节形式
		PublicKeys: [][]byte{bls.G2.ToBytes(apk.pk)},           // 所有参与签名的公钥
	}

	sigRequestJSON, err := json.Marshal(sigRequestSign)
	return sigRequestJSON, err
}

func VerifyPixel(sigRequest SignatureRequest) (bool, error) {
	Apk, err := bls.G2.FromBytes(sigRequest.PublicKeys[0])
	if err != nil {
		return false, fmt.Errorf("FromBytes failed in VerifyPIXEL TAT: %v", err)
	}
	apk := &PublicKey{pk: Apk}
	message := sigRequest.Message

	Q1, err := bls.G1.FromBytes(sigRequest.S[0])
	if err != nil {
		return false, fmt.Errorf("FromBytes failed in VerifyBLS TAT: %v", err)
	}
	Q2, err := bls.G2.FromBytes(sigRequest.R[0])
	if err != nil {
		return false, fmt.Errorf("FromBytes failed in VerifyBLS TAT: %v", err)
	}
	aggregatedSig := &Signature{q1: Q1, q2: Q2}

	return VerifyAg(apk, aggregatedSig, []byte(message), t), nil
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
