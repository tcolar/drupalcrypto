<?php

class uc_encryption_class {

  protected static $scramble1 = '! #$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`"abcdefghijklmnopqrstuvwxyz{|}~';
  protected static $scramble2 = 'f^jAE]okIOzU[2&q1{3`h5w_794p@6s8?BgP>dFV=m" D<TcS%Ze|r:lGK/uCy.Jx)HiQ!#$~(;Lt-R}Ma,NvW+Ynb*0X';

  protected $errors = array();
  protected $adj = 1.75;
  protected $mod = 3;


  /**
   * Decrypts cyphertext.
   *
   * @param $key
   *   String key used for encryption.
   * @param $source
   *   Cyphertext. Text string containing encrypted $source.
   *
   * @return
   *   Plaintext. Text string to be encrypted.
   */
  function decrypt($key, $source) {
    $this->errors = array();

    // Convert key into sequence of numbers
    $fudgefactor = $this->convertKey($key);
    if ($this->errors) {
      return;
    }

    if (empty($source)) {
      // Commented out to prevent errors getting logged for use cases that may
      // have variable encryption/decryption requirements. -RS
      // $this->errors[] = t('No value has been supplied for decryption');
      return;
    }

    $target = NULL;
    $factor2 = 0;

    for ($i = 0; $i < strlen($source); $i++) {
      $char2 = substr($source, $i, 1);

      $num2 = strpos(self::$scramble2, $char2);
      if ($num2 === FALSE) {
        $this->errors[] = t('Source string contains an invalid character (@char)', array('@char' => $char2));
        return;
      }

      $adj = $this->applyFudgeFactor($fudgefactor);
      $factor1 = $factor2 + $adj;
      $num1 = $num2 - round($factor1);
      $num1 = $this->checkRange($num1);
      $factor2 = $factor1 + $num2;

      $char1 = substr(self::$scramble1, $num1, 1);
      $target .= $char1;
    }

    return rtrim($target);
  }

  /**
   * Encrypts plaintext.
   *
   * @param $key
   *   String key used for encryption.
   * @param $source
   *   Plaintext. Text string to be encrypted.
   * @param $sourcelen
   *   Minimum plaintext length.  Plaintext $source which is shorter than
   *   $sourcelen will be padded by appending spaces.
   *
   * @return
   *   Cyphertext. Text string containing encrypted $source.
   */
  function encrypt($key, $source, $sourcelen = 0) {
    $this->errors = array();

    // Convert key into sequence of numbers
    $fudgefactor = $this->convertKey($key);
    if ($this->errors) {
      return;
    }

    if (empty($source)) {
      // Commented out to prevent errors getting logged for use cases that may
      // have variable encryption/decryption requirements. -RS
      // $this->errors[] = t('No value has been supplied for encryption');
      return;
    }

    while (strlen($source) < $sourcelen) {
      $source .= ' ';
    }

    $target = NULL;
    $factor2 = 0;

    for ($i = 0; $i < strlen($source); $i++) {
      $char1 = substr($source, $i, 1);
      echo($char1 . "\n");

      $num1 = strpos(self::$scramble1, $char1);
      if ($num1 === FALSE) {
        $this->errors[] = t('Source string contains an invalid character (@char)', array('@char' => $char1));
        return;
      }
      echo($num1);echo(" <- num1\n");

      $adj = $this->applyFudgeFactor($fudgefactor);
      $factor1 = $factor2 + $adj;
      echo($factor1);echo(" <- factor1\n");
      $num2 = round($factor1) + $num1;
      $num2 = $this->checkRange($num2);
      echo($num2);echo(" <- num2\n");
      $factor2 = $factor1 + $num2;
      $char2 = substr(self::$scramble2, $num2, 1);
      $target .= $char2;
      echo($target . "\n");
    }

    return $target;
  }

  /**
   * Accessor for errors property.
   */
  public function getErrors() {
    return $this->errors;
  }

  /**
   * Mutator for errors property.
   */
  public function setErrors(array $errors) {
    $this->errors = $errors;
  }

  /**
   * Accessor for adj property.
   */
  function getAdjustment() {
    return $this->adj;
  }

  /**
   * Mutator for adj property.
   */
  function setAdjustment($adj) {
    $this->adj = (float) $adj;
  }

  /**
   * Accessor for mod property.
   */
  function getModulus() {
    return $this->mod;
  }

  /**
   * Mutator for mod property.
   */
  function setModulus($mod) {
    $this->mod = (int) abs($mod);
  }

  /**
   * Returns an adjustment value based on the contents of $fudgefactor.
   */
  function applyFudgeFactor(&$fudgefactor) {
    static $alerted = FALSE;

    if (!is_array($fudgefactor)) {
      $fudge = 0;
      if (!$alerted) {
        // Throw an error that makes sense so this stops getting reported.
        $this->errors[] = t('No encryption key was found.');
        drupal_set_message(t('Ubercart cannot find a necessary encryption key.  Refer to the store admin <a href="!url">dashboard</a> to isolate which one.', array('!url' => url('admin/store'))), 'error');

        $alerted = TRUE;
      }
    }
    else {
      $fudge = array_shift($fudgefactor);
    }

    $fudge = $fudge + $this->adj;
    $fudgefactor[] = $fudge;

    if (!empty($this->mod)) {
      if ($fudge % $this->mod == 0) {
        $fudge = $fudge * -1;
      }
    }

    return $fudge;
  }

  /**
   * Checks that $num points to an entry in self::$scramble1.
   */
  function checkRange($num) {
    $num = round($num);
    $limit = strlen(self::$scramble1);

    while ($num >= $limit) {
      $num = $num - $limit;
    }
    while ($num < 0) {
      $num = $num + $limit;
    }

    return $num;
  }

  /**
   * Converts encryption key into an array of numbers.
   *
   * @param $key
   *   Encryption key.
   *
   * @return
   *   Array of integers.
   */
  function convertKey($key) {
    if (empty($key)) {
      // Commented out to prevent errors getting logged for use cases that may
      // have variable encryption/decryption requirements. -RS
      // $this->errors[] = 'No value has been supplied for the encryption key';
      return;
    }

    $array[] = strlen($key);

    $tot = 0;
    for ($i = 0; $i < strlen($key); $i++) {
      $char = substr($key, $i, 1);

      $num = strpos(self::$scramble1, $char);
      if ($num === FALSE) {
        $this->errors[] = "Key contains an invalid character ($char)";
        return;
      }

      $array[] = $num;
      $tot = $tot + $num;
    }

    $array[] = $tot;

    return $array;
  }
}

$enc = new uc_encryption_class();
$b64 = base64_encode('a:9:{s:7:"cc_type";s:10:"Mastercard";s:8:"cc_owner";s:0:"";s:9:"cc_number";s:4:"6441";s:14:"cc_start_month";s:0:"";s:13:"cc_start_year";s:0:"";s:12:"cc_exp_month";s:1:"8";s:11:"cc_exp_year";s:4:"2016";s:8:"cc_issue";s:0:"";s:7:"cc_bank";s:0:"";}');
echo($b64);echo("\n");
$result = $enc->encrypt("111222333dddccccc122456789abcdef", $b64);

var_dump($result);





