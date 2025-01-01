package inputs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// 加密密钥
const EncryptKey = "a3f5e7c9b2d4a6e8"

// 加密密钥
func GetEncryptKey() string {
	return EncryptKey
}

// func main() {
// 	// 16 字节的 AES 密钥（AES-128）
// 	key := []byte("a3f5e7c9b2d4a6e8") // 16 字节密钥

// 	// 需要加密的明文
// 	plaintext := "Q9psxrjoZsXxxNx5C%"

// 	// 加密
// 	ciphertext, err := encrypt(key, plaintext)
// 	fmt.Println(ciphertext)
// 	if err != nil {
// 		fmt.Println("加密失败:", err)
// 		return
// 	}
// 	fmt.Println("加密后的 Base64 字符串:", ciphertext)

// 	// 解密
// 	decryptedText, err := decrypt(key, ciphertext)
// 	if err != nil {
// 		fmt.Println("解密失败:", err)
// 		return
// 	}
// 	fmt.Println("解密后的数据:", decryptedText)
// }

// PKCS7 填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS7 去除填充
func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return nil
	}
	return data[:len(data)-padding]
}

// 加密函数
func EncryptPassword(key []byte, plaintext string) (string, error) {
	// 将明文转换为字节
	plaintextBytes := []byte(plaintext)

	// 填充明文数据
	plaintextBytes = pkcs7Pad(plaintextBytes, aes.BlockSize)

	// 创建 AES 加密块
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 创建初始化向量 (IV)
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 加密数据
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintextBytes)

	// 返回 Base64 编码的密文
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// 解密函数
func DecryptPassword(key []byte, ciphertext string) (string, error) {
	// 解码 Base64 密文
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// 检查密文长度是否合法
	if len(ciphertextBytes) < aes.BlockSize {
		return "", errors.New("密文长度不合法")
	}

	// 提取初始化向量 (IV) 和实际密文
	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	// 创建 AES 解密块
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 解密数据
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertextBytes, ciphertextBytes)

	// 去除填充数据
	plaintextBytes := pkcs7Unpad(ciphertextBytes)
	if plaintextBytes == nil {
		return "", errors.New("解密失败：填充数据无效")
	}

	// 返回解密后的明文
	return string(plaintextBytes), nil
}
