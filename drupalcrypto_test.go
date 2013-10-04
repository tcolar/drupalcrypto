// History: Sep 11 13 tcolar Creation

package drupalcrypto

import(
  "log"
  "testing"
)

func TestCrypto(t *testing.T){
  key := "111222333dddccccc122456789abcdef"
  c := DrupalCrypto()

  result, err := c.Crypt("abc", key)
  if err != nil {log.Fatal(err)}
  if result != "6t-" {log.Fatal("Unexpected result: "+result)}
  result, _ = c.B64Crypt(`a:9:{s:7:"cc_type";s:10:"Mastercard";s:8:"cc_owner";s:0:"";s:9:"cc_number";s:4:"0882";s:14:"cc_start_month";s:0:"";s:13:"cc_start_year";s:0:"";s:12:"cc_exp_month";s:1:"4";s:11:"cc_exp_year";s:4:"2016";s:8:"cc_issue";s:0:"";s:7:"cc_bank";s:0:"";}`,
    key)

  test := `a:9:{s:7:"cc_type";s:10:"Mastercard";s:8:"cc_owner";s:0:"";s:9:"cc_number";s:4:"6441";s:14:"cc_start_month";s:0:"";s:13:"cc_start_year";s:0:"";s:12:"cc_exp_month";s:1:"8";s:11:"cc_exp_year";s:4:"2016";s:8:"cc_issue";s:0:"";s:7:"cc_bank";s:0:"";}`
  result, err = c.Crypt(test, key)
  if err != nil {log.Fatal(err)}
  result, err = c.Decrypt(result, key)
  if err != nil {log.Fatal(err)}
  if result != test {
    log.Fatal("Unexpected result: " + result)
  }
  result, err = c.B64Crypt(test, key)
  if err != nil {log.Fatal(err)}
  result, err = c.B64Decrypt(result, key)
  if err != nil {log.Fatal(err)}
  if result != test {
    log.Fatal("Unexpected result: " + result)
  }

  result, err = c.B64Crypt(test, key)
  if err != nil {log.Fatal(err)}
  log.Print(result)
}

