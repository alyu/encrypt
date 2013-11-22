package encrypt

import "fmt"

func ExampleEncrypt() {
	text := "Two roads diverged in a yellow wood"
	// 32 bytes
	secretKey := []byte("1m!Cn25GW2frzDefg)^q2koE(4K2vIQX")
	encrypted := Encrypt(secretKey, []byte(text))
	fmt.Println(EncodeBase64(encrypted))
	fmt.Println("sha1:", Sha1([]byte(text)))
	// Output:
	// pLJGOMRo4IxI/wAiLe5dhFYCiwcCMCpa80JzTunHBYY3S3q2E3YhiShGmVOHx55NENjwzAaSmsjlhDlc7wHWQQ==
	// sha1: 97d2ce306525e5036b6a39737d8ac415869f6e4c
}

func ExampleDecrypt() {
	encrypted := "pLJGOMRo4IxI/wAiLe5dhFYCiwcCMCpa80JzTunHBYY3S3q2E3YhiShGmVOHx55NENjwzAaSmsjlhDlc7wHWQQ=="
	text := "Two roads diverged in a yellow wood"
	// 32 bytes
	secretKey := []byte("1m!Cn25GW2frzDefg)^q2koE(4K2vIQX")
	decrypt := Decrypt(secretKey, []byte(DecodeBase64(encrypted)))
	fmt.Println(decrypt)
	sha1 := Sha1([]byte(decrypt))
	sha2 := Sha1([]byte(text))
	fmt.Println("sha1:", sha1, "sha2:", sha2)
	// Output:
	// Two roads diverged in a yellow wood
	// sha1: 97d2ce306525e5036b6a39737d8ac415869f6e4c sha2: 97d2ce306525e5036b6a39737d8ac415869f6e4c
}
