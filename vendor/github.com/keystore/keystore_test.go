package keystore

import (
	"fmt"
	"testing"
)

var (
	privateKey = "L42HUaRadQboiWb8QtUyupddFhh2pfuJuA6RYB1Z2XPAG2mjUp6H"
)

// func TestGeneralKeystore(t *testing.T) {
// 	//
// 	json, err := GenerateKeystore("L42HUaRadQboiWb8QtUyupddFhh2pfuJuA6RYB1Z2XPAG2mjUp6H", "11111")
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}

// 	fmt.Println("Keystore file: \n", json)

// 	priv, err := DecodeKeystore(json, "11111")
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	fmt.Println("私钥：", priv)
// }

func TestGeneralKeystore(t *testing.T) {
	udid := "SFWER-23QWE--EQBZW-QEWDE-HOIJSD"
	pwd := "11111"
	newJson, err := EncryptKey(privateKey, pwd,udid)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Keystore file: \n", newJson)
	priv, err := DecryptKey(newJson, pwd,udid)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Privated Key: \n", priv)

}
