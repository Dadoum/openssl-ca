module infiniteloop.openssl.evp;

import std.conv;
import std.exception : enforce;
import std.string : toStringz;

/* External modules imports */
import deimos.openssl.evp;
import deimos.openssl.pem;

/* Module-local imports */
import infiniteloop.openssl.bio;
import infiniteloop.openssl.error;
import infiniteloop.openssl.password;

// Brought from openssl v1.1.1:
enum EVP_PKEY_ED25519 = 1087; // "NID_ED25519 = 1087" declared in "obj_mac.h", NID_ED25519 declared in "evp.h".

enum KeyType
{
  RSA = EVP_PKEY_RSA,
  ED25519 = EVP_PKEY_ED25519
}

enum Chiper
{
  AES_256_CBC
}

const(EVP_CIPHER)* getEvpChiper(Chiper chiper)
{
  switch (chiper)
  {
  default:
    return EVP_aes_256_cbc();
  case Chiper.AES_256_CBC:
    return EVP_aes_256_cbc();
  }
}

enum MessageDigest
{
  NONE,
  SHA_256
}

const(EVP_MD)* getEvpMessageDigest(MessageDigest md)
{
  switch (md)
  {
  default:
    return EVP_sha256();
  case MessageDigest.SHA_256:
    return EVP_sha256();
  case MessageDigest.NONE:
    return null;
  }
}

/**
 * Wrapper for C struct 'EVP_PKEY' which represents an algorithm-independent cryptographic key.
 */
class EVPKey
{
  private EVP_PKEY* key;

public:

  this()
  {
    key = EVP_PKEY_new();
  }

  protected this(EVP_PKEY* key)
  {
    this.key = key;
  }

  KeyType getKeyType() const
  {
    return to!KeyType(EVP_PKEY_base_id(this.key));
  }

  /**
   * Read in an existing key from string.
   */
  this(const string pemFormattedKey, const string password = "")
  {
    auto bio = new Bio(
      (BIO* mem) => null != PEM_read_bio_PrivateKey(mem, &key, &passwordCallbackWrapper, cast(
        void*) toStringz(password))
    );
    bio.fromStr(pemFormattedKey);
  }

  ~this()
  {
    EVP_PKEY_free(key);
  }

  const(string) toPEM(const string password = "", Chiper chiper = Chiper.AES_256_CBC)
  {
    if (password.length)
    {
      return toPEM(new Password(password, chiper));
    }
    else
    {
      return toPEM(new Password());
    }
  }

  /**
   * Writes in PKCS#8
   */
  private  /*const (ver >= 1.1.0h) */ const(string) toPEM(Password password)
  {
    auto bio = new Bio(
      (BIO* mem) => 1 == PEM_write_bio_PrivateKey(mem, key, password.getChiper(), password.getPassword(),
        password.getLength(), null  /* password callback */ , null  /* callback data */ )
    );
    return bio.to!string;
  }

  /**
   * Used with C api.
   */
  EVP_PKEY* c_type()
  {
    return key;
  }

  /**
   * Used with C api.
   */
  const(EVP_PKEY)* c_type_const() const
  {
    return key;
  }
}
