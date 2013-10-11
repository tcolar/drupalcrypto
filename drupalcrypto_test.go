// History: Sep 11 13 tcolar Creation

package drupalcrypto

import (
	"encoding/base64"
	"log"
	"testing"
)

func TestCrypto(t *testing.T) {
	key := "111222333dddccccc122456789abcdef"
	c := DrupalCrypto()
	var err error
	var result string

	result, err = c.Crypt("abc", key)
	if err != nil {
		log.Fatal(err)
	}
	if result != "6t-" {
		log.Fatal("Unexpected result: " + result)
	}

	// check against known php implementation
	test := `a:9:{s:7:"cc_type";s:10:"Mastercard";s:8:"cc_owner";s:0:"";s:9:"cc_number";s:4:"6441";s:14:"cc_start_month";s:0:"";s:13:"cc_start_year";s:0:"";s:12:"cc_exp_month";s:1:"8";s:11:"cc_exp_year";s:4:"2016";s:8:"cc_issue";s:0:"";s:7:"cc_bank";s:0:"";}`
	result, _ = c.B64Crypt(test, key)

	expected := "5:u-U$(=3<KD,=L`Ta7dDMO16:1;ZmdVp3&x[Z/Q:<Mhu/`d7nW6)<CX]YWBbxu{8dFNvQb,(_i/2aKo=vr8/>y>Bea*!k6QK]%I=>wAu(DnmSWX7y`)qRc^lH84ylr&!+G0ScooPT9!!vGps1Ab4ui:.-3aiLwZG7%[4bfaf6jA~V!$KWP;2;)8z@7u`E<8%^*RaLI)E<h6jm%&|@:[>~]p\"mX|3@l=,6j3c/c@b-OX.|Wd0_?%dQF&b$5CM9.Ym\"Egk-l>i|Y%>&oaZAdL~ ?u<Lj}76>\"wlQN)6yEF+ZXISANSh92Tes(f/z>&m.@op[<EV\"V"

	if result != expected {
		bytes := []byte(test)
		b64 := base64.StdEncoding.EncodeToString(bytes)
		log.Print("Base 64  \t" + b64)
		log.Print("Enc. Key \t" + key)
		log.Print("Raw Data \t" + test)
		log.Print("Expected \t" + expected)
		log.Print("Returned \t" + result)
		log.Fatal("Unexpected resut")
	}

	result, err = c.Crypt(test, key)
	if err != nil {
		log.Fatal(err)
	}
	result, err = c.Decrypt(result, key)
	if err != nil {
		log.Fatal(err)
	}
	if result != test {
		log.Fatal("Unexpected result: " + result)
	}
	result, err = c.B64Crypt(test, key)
	if err != nil {
		log.Fatal(err)
	}
	result, err = c.B64Decrypt(result, key)
	if err != nil {
		log.Fatal(err)
	}
	if result != test {
		log.Fatal("Unexpected result: " + result)
	}

	result, err = c.B64Crypt(test, key)
	if err != nil {
		log.Fatal(err)
	}
	//log.Print(result)
}
