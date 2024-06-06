package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// CFB模式加密

// stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)：使用加密流对明文进行加密。
// CFB模式使用IV，使加密更安全，即使相同的明文每次加密产生不同的密文。

// CFB模式是一种将块加密算法（如AES）转换为流加密算法的模式。
// 在CFB模式中，明文被分成若干个分组，然后依次加密，每个分组的加密依赖于前一个分组的密文。IV用于第一个分组的加密。
func encryptAESCFB(key, plaintext []byte) (string, error) {

	// aes.NewCipher(key)：创建一个AES密码块实例。密钥长度必须是16、24或32字节。
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	//AES CFB加密后的密文长度通常会略大于明文长度
	//ciphertext：分配一个新的字节切片，长度为AES块大小加上明文长度，用于存储密文。
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// iv：初始化向量，AES加密需要一个随机的IV来确保相同的明文在不同的加密操作中产生不同的密文。
	// 密文的前 aes.BlockSize 字节存储了 IV，而剩余的部分则是加密后的数据。在解密时，首先需要从密文中提取出 IV，并将剩余部分作为解密输入。
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	//cipher.Block 接口定义了 AES 加密和解密算法所需的方法
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

// CFB模式解密
func decryptAESCFB(key []byte, ciphertext string) (string, error) {
	decodedCiphertext, err := hex.DecodeString(ciphertext)

	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(decodedCiphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := decodedCiphertext[:aes.BlockSize]
	decodedCiphertext = decodedCiphertext[aes.BlockSize:]

	//创建一个CFB解密流
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decodedCiphertext, decodedCiphertext)
	return string(decodedCiphertext), nil
}

// ECB模式加密
func encryptAESECB(key []byte, plaintext string) string {
	//创建一个AES密码块
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//调用pad函数对明文进行填充，以确保其长度是AES块大小（16字节）的整数倍。
	plaintextBytes := pad([]byte(plaintext), aes.BlockSize)
	//创建一个与填充后的明文长度相同的字节切片，用于存储密文。
	ciphertext := make([]byte, len(plaintextBytes))
	//逐块加密明文
	for bs, be := 0, block.BlockSize(); bs < len(plaintextBytes); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		//每个块的明文加密成密文，并存储在ciphertext中
		block.Encrypt(ciphertext[bs:be], plaintextBytes[bs:be])
	}
	return hex.EncodeToString(ciphertext)
}

// ECB模式解密
func decryptAESECB(key []byte, ciphertext string) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	decodedCiphertext, _ := hex.DecodeString(ciphertext)
	plaintext := make([]byte, len(decodedCiphertext))
	for bs, be := 0, block.BlockSize(); bs < len(decodedCiphertext); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(plaintext[bs:be], decodedCiphertext[bs:be])
	}
	//unpad函数去除填充，并将字节切片转换为字符串
	return string(unpad(plaintext))
}

// 填充函数
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// 去填充函数，移除填充字节
func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func main() {
	key := []byte("example key12345") //密钥必须是16、24或32字节
	plaintext := "Hello, World!"

	// CFB
	ciphertextCFB, err := encryptAESCFB(key, []byte(plaintext))
	if err != nil {
		fmt.Println("Error encrypting (CFB):", err)
		return
	}
	decryptedCFB, err := decryptAESCFB(key, ciphertextCFB)
	if err != nil {
		fmt.Println("Error decrypting (CFB):", err)
		return
	}
	fmt.Println("Encrypted (CFB):", ciphertextCFB)
	fmt.Println("Decrypted (CFB):", decryptedCFB)

	// ECB
	ciphertextECB := encryptAESECB(key, plaintext)
	decryptedECB := decryptAESECB(key, ciphertextECB)
	fmt.Println("Encrypted (ECB):", ciphertextECB)
	fmt.Println("Decrypted (ECB):", decryptedECB)

}
