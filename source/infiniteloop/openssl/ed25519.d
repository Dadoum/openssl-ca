module infiniteloop.openssl.ed25519;

import std.exception : enforce;

/* External modules imports */
import deimos.openssl.evp;

/* Module-local imports */
import infiniteloop.openssl.evp;
import infiniteloop.openssl.error;

class Ed25519Key : EVPKey
{
  this()
  {
    EVP_PKEY* key = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, null);
    enforce!OpenSSLError(1 == EVP_PKEY_keygen_init(ctx), "Failed to initialize ed25519 key");
    enforce!OpenSSLError(1 == EVP_PKEY_keygen(ctx, &key), "Failed to create ed25519 key");
    EVP_PKEY_CTX_free(ctx);
    super(key);
  }

  unittest  /* Output key type ED25519 */
  {
    auto evpKey = new Ed25519Key();
    assert(evpKey.getKeyType() == KeyType.ED25519, "Expected to return key type ED25519");
  }
}
