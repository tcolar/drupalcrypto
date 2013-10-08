// History: Oct 02 13 tcolar Creation

package drupalcrypto

import (
  "encoding/base64"
  "errors"
  "log"
  "math"
  "strings"
)

type PhpCrypto struct {
  Scramble1 string
  Scramble2 string
  Adj       float64
  Mod       int
}

// Get a Crypto instance initialized as it is in Drupal / Ubbercart
func DrupalCrypto() (crypto PhpCrypto) {
  return PhpCrypto{
    Scramble1: "! #$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`\"abcdefghijklmnopqrstuvwxyz{|}~",
    Scramble2: "f^jAE]okIOzU[2&q1{3`h5w_794p@6s8?BgP>dFV=m\" D<TcS%Ze|r:lGK/uCy.Jx)HiQ!#$~(;Lt-R}Ma,NvW+Ynb*0X",
    Adj:       1.75,
    Mod:       3,
  }
}

// This is how some Drupal data is encrypted (convert to b64 first)
func (crypto PhpCrypto) B64Crypt(data string, encKey string) (result string, err error) {
  // First to base64
  bytes := []byte(data)
  b64 := base64.StdEncoding.EncodeToString(bytes)
  return crypto.Crypt(b64, encKey)
}

func (crypto PhpCrypto) Crypt(data string, encKey string) (result string, err error) {

  var fudgefactor []float64
  fudgefactor, err = crypto.convertKey(encKey)
  if err != nil {
    return result, err
  }

  var factor2 float64

  for _, c := range data {
    c1 := string(c)
    num1 := strings.Index(crypto.Scramble1, c1)
    if num1 < 0 {
      return result, errors.New("Source string contains an invalid character : " + c1)
    }
    //log.Printf("%d num1", num1)

    adj := crypto.applyFudgeFactor(&fudgefactor)
    factor1 := factor2 + adj
    //log.Printf("%f factor1", factor1)
    num2 := int(Rounded(factor1, 0)) + num1
    num2 = crypto.checkRange(num2)
    //log.Printf("%d num2", num2)
    factor2 = factor1 + float64(num2)

    char2 := crypto.Scramble2[num2 : num2+1]
    result += char2
  }

  return result, err
}

// This is how some Drupal data is encrypted
func (crypto PhpCrypto) B64Decrypt(data string, encKey string) (result string, err error) {
  str, err := crypto.Decrypt(data, encKey)
  if err != nil {
    return result, err
  }
  log.Print(str)
  decoded, err := base64.StdEncoding.DecodeString(str)
  return string(decoded), err
}

func (crypto PhpCrypto) Decrypt(data string, encKey string) (result string, err error) {
  // Convert key into sequence of numbers
  if len(data) == 0 {
    return result, errors.New("No data supplied.")
  }

  var fudgefactor []float64
  fudgefactor, err = crypto.convertKey(encKey)
  if err != nil {
    return result, err
  }

  var factor2 float64

  for _, c := range data {
    c2 := string(c)
    num2 := strings.Index(crypto.Scramble2, c2)
    if num2 < 0 {
      return result, errors.New("Key contains an invalid character : " + c2)
    }

    adj := crypto.applyFudgeFactor(&fudgefactor)
    factor1 := factor2 + adj
    num1 := num2 - int(Rounded(factor1, 0))
    num1 = crypto.checkRange(num1)
    factor2 = factor1 + float64(num2)

    char1 := crypto.Scramble1[num1 : num1+1]
    result += char1
  }

  return result, err
}

func (crypto PhpCrypto) convertKey(key string) (result []float64, err error) {
  result = append(result, float64(len(key)))
  tot := 0.0

  for _, c := range key {
    num := strings.IndexRune(crypto.Scramble1, c)
    if num < 0 {
      return result, errors.New("Key contains an invalid character : " + string(c))
    }
    result = append(result, float64(num))
    tot += float64(num)
  }
  result = append(result, tot)

  return result, err
}

func (crypto PhpCrypto) applyFudgeFactor(fudgefactor *[]float64) (fudge float64) {
  f := *fudgefactor
  fudge = f[0]         // take first element
  *fudgefactor = f[1:] // remove it from array

  fudge += crypto.Adj
  *fudgefactor = append(*fudgefactor, fudge)

  if int(fudge)%crypto.Mod == 0 {
    fudge *= -1
  }

  return fudge
}

func (crypto PhpCrypto) checkRange(input int) (num int) {
  num = input
  //num = Rounded(num, 0)
  limit := len(crypto.Scramble1)

  for num >= limit {
    num = num - limit
  }
  for num < 0 {
    num = num + limit
  }
  return num
}

func Rounded(val float64, decimals int) (rounded float64) {
  var rounder float64
  pow := math.Pow(10, float64(decimals))
  intermed := val * pow
  _, frac := math.Modf(intermed)
  if frac >= 0.5 {
    rounder = math.Ceil(intermed)
  } else {
    rounder = math.Floor(intermed)
  }
  return rounder / pow
}