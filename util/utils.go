package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
)

const (
	token          = ""//替换开发申请的
	encodingAESKey = ""//替换开发申请的
	Corpid         = ""//替换开发申请的
)

func VerifyURL(msgSignature, timeStamp, nonce, echoStr string) (string, AesException) {
	signature := getSHA1(token, timeStamp, nonce, echoStr)

	if signature != msgSignature {
		return "", ValidateSignatureError
	}

	result, exception := decrypt(echoStr)
	return result, exception
}

func getSHA1(token, timeStamp, nonce, encrypt string) string {
	strs := sort.StringSlice{token, timeStamp, nonce, encrypt}
	strs.Sort()
	buf := make([]byte, 0, len(token)+len(timeStamp)+len(nonce)+len(encrypt))
	buf = append(buf, strs[0]...)
	buf = append(buf, strs[1]...)
	buf = append(buf, strs[2]...)
	buf = append(buf, strs[3]...)
	hashsum := sha1.Sum(buf)
	return hex.EncodeToString(hashsum[:])
}

type AesException struct {
	Code int
	Desc string
}

var (
	OK                     = AesException{0, "OK"}
	ValidateSignatureError = AesException{-40001, "Validate Signature Error"}
	ParseXmlError          = AesException{-40002, "Parse Xml Error"}
	ComputeSignatureError  = AesException{-40003, "Compute Signature Error"}
	IllegalAesKey          = AesException{-40004, "Illegal Aes Key Error"}
	ValidateCorpidError    = AesException{-40005, "Validate Corpid Error"}
	EncryptAESError        = AesException{-40006, "Encrypt AES Error"}
	DecryptAESError        = AesException{-40007, "Decrypt AES Error"}
	IllegalBuffer          = AesException{-40008, "Illegal Buffer"}
	EncodeBase64Error      = AesException{-40009, "Encode Base64 Error"}
	DecodeBase64Error      = AesException{-40010, "Decode Base64 Error"}
	GenReturnXmlError      = AesException{-40011, "GenReturn Xml Error"}
)

func decrypt(echoStr string) (string, AesException) {
	ciphertext, err := base64.StdEncoding.DecodeString(echoStr)
	if err != nil {
		//log.Error("base64 decrypt err:%v", err)
		return "", DecodeBase64Error
	}
	decodingAESKey, err := base64.StdEncoding.DecodeString(encodingAESKey)
	if err != nil {
		//log.Error("base64 decrypt err:%v", err)
		return "", DecodeBase64Error
	}
	_, rawXMLMessage, corpid, err := AESDecryptMsg(ciphertext, decodingAESKey)
	if err != nil {
		//log.Error("aes decrypt err:%v", err)
		return "", DecryptAESError
	}
	if !bytes.Equal(corpid, []byte(Corpid)) {
		return "", ValidateCorpidError
	}
	return string(rawXMLMessage), OK
}

func AESDecryptMsg(ciphertext []byte, aesKey []byte) (random, rawXMLMsg, appId []byte, err error) {
	const (
		BLOCK_SIZE = 32             // PKCS#7
		BLOCK_MASK = BLOCK_SIZE - 1 // BLOCK_SIZE 为 2^n 时, 可以用 mask 获取针对 BLOCK_SIZE 的余数
	)

	if len(ciphertext) < BLOCK_SIZE {
		err = fmt.Errorf("the length of ciphertext too short: %d", len(ciphertext))
		return
	}
	if len(ciphertext)&BLOCK_MASK != 0 {
		err = fmt.Errorf("ciphertext is not a multiple of the block size, the length is %d", len(ciphertext))
		return
	}

	plaintext := make([]byte, len(ciphertext)) // len(plaintext) >= BLOCK_SIZE

	// 解密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, aesKey[:16])
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS#7 去除补位
	amountToPad := int(plaintext[len(plaintext)-1])
	if amountToPad < 1 || amountToPad > BLOCK_SIZE {
		err = fmt.Errorf("the amount to pad is incorrect: %d", amountToPad)
		return
	}
	plaintext = plaintext[:len(plaintext)-amountToPad]

	// 反拼接
	// len(plaintext) == 16+4+len(rawXMLMsg)+len(appId)
	if len(plaintext) <= 20 {
		err = fmt.Errorf("plaintext too short, the length is %d", len(plaintext))
		return
	}
	rawXMLMsgLen := int(decodeNetworkByteOrder(plaintext[16:20]))
	if rawXMLMsgLen < 0 {
		err = fmt.Errorf("incorrect msg length: %d", rawXMLMsgLen)
		return
	}
	appIdOffset := 20 + rawXMLMsgLen
	if len(plaintext) <= appIdOffset {
		err = fmt.Errorf("msg length too large: %d", rawXMLMsgLen)
		return
	}

	random = plaintext[:16:20]
	rawXMLMsg = plaintext[20:appIdOffset:appIdOffset]
	appId = plaintext[appIdOffset:]
	return
}

// 从 4 字节的网络字节序里解析出整数
func decodeNetworkByteOrder(b []byte) (n uint32) {
	return uint32(b[0])<<24 |
		uint32(b[1])<<16 |
		uint32(b[2])<<8 |
		uint32(b[3])
}
