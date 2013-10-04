drupalcrypto
============

Encoding / decoding of Drupal UberCart encrypted data which is encrypted using this format:

http://api.ubercart.me/api/drupal/ubercart%21uc_store%21uc_store.module/class/uc_encryption_class/6

which is based on this:

http://www.tonymarston.co.uk/php-mysql/encryption.html

I don't recommand anybody using this for crypto, this is rather obsolete and I doubt that it's safe or good,
but I had to work from GoLang with a Drupal databases whose module (ubercart) stored some data using this encryption format, so here it is.