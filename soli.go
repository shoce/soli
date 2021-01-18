/*
history:
2020/04/28 v1

go get -u -v github.com/keys-pub/keys/...

GoFmt GoBuildNull GoRun GoBuild GoRelease
*/

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
)

var (
	k  keys.Key
	kr saltpack.Keyring

	key, id string

	configPath = "$HOME/config/soli"
	keyPath    = configPath + "/key.text"
	idPath     = configPath + "/id.text"
)

func init() {
	keyPath = os.ExpandEnv(keyPath)
	idPath = os.ExpandEnv(idPath)
}

func saveKey(key, id string) error {
	var err error
	if key == "" || id == "" {
		return fmt.Errorf("key or id empty")
	}

	if _, err = os.Stat(keyPath); os.IsNotExist(err) {
		err = ioutil.WriteFile(keyPath, []byte(key), 0600)
		if err != nil {
			return err
		}
	}
	if _, err = os.Stat(idPath); os.IsNotExist(err) {
		err = ioutil.WriteFile(idPath, []byte(id), 0600)
		if err != nil {
			return err
		}
	}
	return nil
}

func getKey() (key, id string, err error) {
	if os.ExpandEnv("$HOME") == "" {
		return "", "", fmt.Errorf("$HOME empty")
	}

	bkey, _ := ioutil.ReadFile(keyPath)
	bid, _ := ioutil.ReadFile(idPath)

	key = string(bkey)
	id = string(bid)

	if key != "" {
		k, err = keys.DecodeSaltpackKey(key, "", false)
		if err != nil {
			return "", "", err
		}
	} else {
		k = keys.GenerateEdX25519Key()
		key, err = keys.EncodeSaltpackKey(k, "")
		if err != nil {
			return "", "", err
		}
	}

	id = string(k.ID())

	err = saveKey(key, id)
	if err != nil {
		return "", "", err
	}

	kr = saltpack.NewKeyring(k)
	if err != nil {
		return "", "", err
	}

	//fmt.Fprintf(os.Stderr, "Key:0x%s\n", hex.EncodeToString(k.Bytes()))

	return key, id, nil
}

func main() {
	var err error

	_, _, err = getKey()
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		fmt.Println(strings.TrimSpace(`
usage: soli command
commands:
	encrypt
	decrypt
	key
`))
		os.Exit(1)
	}

	cmd := os.Args[1]
	var args []string
	if len(os.Args) > 2 {
		args = os.Args[2:]
	}

	if cmd == "encrypt" {

		w, err := saltpack.NewEncryptStream(os.Stdout, true, nil, k.ID())
		if err != nil {
			log.Fatal(err)
		}

		_, err = io.Copy(w, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}

		err = w.Close()
		if err != nil {
			log.Fatal(err)
		}

	} else if cmd == "decrypt" {

		r, _, err := saltpack.NewDecryptStream(os.Stdin, true, kr)
		if err != nil {
			log.Fatal(err)
		}

		_, err = io.Copy(os.Stdout, r)
		if err != nil {
			log.Fatal(err)
		}

		err = os.Stdout.Close()
		if err != nil {
			log.Fatal(err)
		}

	} else if cmd == "key" && len(args) > 0 {

		newkey := args[0]
		nkn := new(big.Int)
		_, ok := nkn.SetString(newkey, 0)
		if !ok {
			log.Fatal("invalid new key string")
		}
		nkbb := nkn.Bytes()
		fmt.Printf("(%d*bytes)%v\n", len(nkbb), nkbb)

	} else if cmd == "key" {

		kbb := k.Private()

		kn := new(big.Int)
		kn.SetBytes(kbb)
		kb32 := kn.Text(32)
		kb16 := kn.Text(16)
		kb10 := kn.Text(10)
		kb9 := kn.Text(9)
		kb8 := kn.Text(8)
		kb7 := kn.Text(7)
		kb6 := kn.Text(6)
		kb5 := kn.Text(5)
		kb4 := kn.Text(4)
		kb3 := kn.Text(3)
		kb2 := kn.Text(2)

		fmt.Printf(""+
			"id=%s\n"+
			"(%d*bytes)%v\n"+
			"(%d*base32)%s\n"+
			"(%d*base16)%s\n"+
			"(%d*base10)%s\n"+
			"(%d*base9)%s\n"+
			"(%d*base8)%s\n"+
			"(%d*base7)%s\n"+
			"(%d*base6)%s\n"+
			"(%d*base5)%s\n"+
			"(%d*base4)%s\n"+
			"(%d*base3)%s\n"+
			"(%d*base2)%s\n"+
			"",
			k.ID(),
			len(kbb), kbb,
			len(kb32), kb32,
			len(kb16), kb16,
			len(kb10), kb10,
			len(kb9), kb9,
			len(kb8), kb8,
			len(kb7), kb7,
			len(kb6), kb6,
			len(kb5), kb5,
			len(kb4), kb4,
			len(kb3), kb3,
			len(kb2), kb2,
		)

	} else {

		log.Fatalf("unknown subcommand `%s`", cmd)

	}

	return
}
