module infiniteloop.openssl.stubs.rsa;

import infiniteloop.openssl.rsa : RsaKey, RsaKeyConfig;

/**
 * RsaKey used in tests to not generate new keys for each unittest.
 */
static RsaKey key;
static RsaKey anotherKey;

static this()
{
  key = new RsaKey(RsaKeyConfig(512));
  anotherKey = new RsaKey(RsaKeyConfig(512));
}
