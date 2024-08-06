# AES加密
- **密钥长度**：支持128位、192位和256位密钥。
- **分组长度**：固定为128位（16字节）。
- **操作原理**：AES本身是块加密算法，为了加密数据块之外的数据，需要结合不同的操作模式。这些模式决定了如何处理多块数据及如何使用初始化向量（IV）。以下是AES的几种常见模式：


#### 加密模式

加密模式（Cipher Mode）是指在 **对称加密** 中，如何处理超过一个块的数据。

#### 1. ECB模式（电子密码本模式，Electronic Codebook Mode）

- **工作原理**：每个块独立加密，不使用IV。
- **优点**：实现简单。
- **缺点**：相同的明文块会被加密成相同的密文块，容易被模式分析。
- **使用场景**：不推荐用于加密大量数据，主要用于单一数据块或对随机数据加密。

```go
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
```

#### 2. CBC模式（密码分组链接模式，Cipher Block Chaining Mode）

- **工作原理**：每个明文块在加密前与前一个密文块进行XOR操作，第一个块使用IV。
- **优点**：相同的明文块在不同位置加密得到不同的密文。
- **缺点**：加密需要顺序处理，无法并行；必须确保IV的随机性。
- **使用场景**：广泛用于加密文件和数据传输。

#### 3. CFB模式（密码反馈模式，Cipher Feedback Mode）

- **工作原理**：将前一密文块（或IV）通过加密块处理后与明文块进行XOR，得到密文块。
- **优点**：可以作为流加密，处理不定长度的数据。
- **缺点**：同样需要顺序处理，无法并行。
- **使用场景**：适用于需要流加密的场景，如加密流式数据。

```go
// 在CFB模式中，明文被分成若干个分组，然后依次加密，每个分组的加密依赖于前一个分组的密文。IV用于第一个分组的加密。
func EncryptAES_CFB(key, plaintext []byte) (string, error) {

	// aes.NewCipher(key)：创建一个AES密码块实例。密钥长度必须是16、24或32字节。
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errmomo CmoC
	}
	//AES CFB加密后的密文长度通常会略大于明文长度
	//ciphertext：分配一个新的字节切片，长度为AES块大小加上明文长度，用于存储密文。
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// iv：初始化向量，AES加密需要一个随机的IV来确保相同的明文在不同的加密操作中产生不同的密文。
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
```

#### 4. CTR模式（计数器模式，Counter Mode）

- **工作原理**：使用一个计数器的加密输出与明文进行XOR，计数器对每个块进行加法操作，确保唯一性。
- **优点**：可以并行处理，加密效率高；块位置可以随机访问。
- **缺点**：计数器必须唯一且不可重复，管理复杂。
- **使用场景**：适合高性能需求的场景，如硬盘加密、网络数据加密。


#### 具体代码
https://github.com/SUMOMO1999/LearnEncrypt_Sumomo/blob/main/src/AES.go

