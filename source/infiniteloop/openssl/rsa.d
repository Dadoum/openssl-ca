module infiniteloop.openssl.rsa;

import core.stdc.stdlib;
import core.stdc.string;
import std.conv:to;
import std.format:format;
import std.string:toStringz;

/* External modules imports */
import deimos.openssl.pem;
import deimos.openssl.rsa;

/* Module-local imports */
import infiniteloop.openssl.evp;
import infiniteloop.openssl.bio;
import infiniteloop.openssl.error;
import infiniteloop.openssl.password;

/**
 * Configuration parameters for creating a new RSA key.
 */
struct RsaKeyConfig
{
    const int bits = 2048;
    const int exp = 3;
}

/**
 * Wrapper for C struct 'RSA' key.
 *
 * Reference:
 * https://github.com/openssl/openssl/blob/OpenSSL_1_1_0-stable/apps/genrsa.c
 * https://github.com/openssl/openssl/blob/OpenSSL_1_1_0-stable/apps/rsa.c
 */
class RsaKey
{
    private RSA *rsaKey;

    /**
     * Creates a new RSA Key according to configuration
     */
    this(const RsaKeyConfig config)
    {
        rsaKey = newKey(config);
    }

    unittest /* Generate RSA key */
    {
        import std.exception:assertNotThrown;
        assertNotThrown!OpenSSLError(
            new RsaKey(RsaKeyConfig(512)), "Expects to successfully create RSA key using correct key configuration"
        );
    }

    unittest /* Generate invalid RSA key */
    {
        import std.exception:assertThrown;
        assertThrown!OpenSSLError(
            new RsaKey(RsaKeyConfig(0)), "Expects to fail create RSA key using incorrect key configuration"
        );
    }

    unittest /* Validate RSA private key */
    {
        auto key = new RsaKey(RsaKeyConfig(512));
        assert(1 == RSA_check_key(key.c_type()), "RSA key validation expects to succeed");
    }

    /**
     * Read in an existing RSA key from string.
     */
    this(const string pemFormattedKey, const string password = "")
    {
        auto bio = new Bio(
            (BIO* mem) => null != PEM_read_bio_RSAPrivateKey(mem, &rsaKey, &passwordCallbackWrapper,
                                        cast(void*)toStringz(password))
        );
        bio.fromStr(pemFormattedKey);
    }

    unittest /* Read an existing RSA key from string */
    {
        import std.exception:assertNotThrown;
        auto key = new RsaKey(RsaKeyConfig(512));
        assertNotThrown!OpenSSLError(
            new RsaKey(key.toPEM()), "RSA key is expected to successfully be created from a PEM formatted string"
        );
    }

    unittest /* Read an existing password-protected RSA key from string, password protected */
    {
        import std.exception:assertNotThrown;
        string password = "secret";
        auto key = new RsaKey(RsaKeyConfig(512));
        assertNotThrown!OpenSSLError(
            new RsaKey(key.toPEM(password), password), "Password protected RSA key is expected to successfully be created from a PEM formatted string"
        );
    }

    unittest /* Read an existing password-protected RSA key from string, with incorrect password*/
    {
        import infiniteloop.openssl.stubs.rsa:key;
        import std.exception:assertThrown;
        auto keyDecoded = key.toPEM("secret");
        assertThrown!OpenSSLError(
            new RsaKey(keyDecoded, "faulty-password"), "Expects to fail reading RSA key with incorrect password"
        );
    }

    ~this()
    {
        RSA_free(rsaKey);
    }

    private RSA* newKey(const RsaKeyConfig config) const
    {
        RSA *key = RSA_new();
        BIGNUM *exponent = BN_new();
        BN_set_word(exponent, config.exp);
        immutable int res = RSA_generate_key_ex(key, config.bits, exponent, null /* callback */);
        // ver >= 1.1.0h: RSA_generate_multi_prime_key(key, config.bits, config.primes, exponent, null /* callback */);
        BN_free(exponent);
        if (res != 1)
        {
            throw new OpenSSLError("Failed to generate RSA key");
        }
        return key;
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

    private const(string) toPEM(Password password)
    {
        auto bio = new Bio(
            (BIO* mem) => 1 == PEM_write_bio_RSAPrivateKey(mem, rsaKey, password.getChiper(), password.getPassword(),
                                    password.getLength(), null /* password callback */, null /* callback data */ )
        );
        return bio.to!string;
    }

    unittest /* Output private key in ascii */
    {
        import std.algorithm:startsWith, endsWith;
        auto key = new RsaKey(RsaKeyConfig(512));
        string str = key.toPEM();
        assert(startsWith(str, "-----BEGIN RSA PRIVATE KEY-----", ), "PEM formatted RSA key expects to have a matching header");
        assert(endsWith(str, "-----END RSA PRIVATE KEY-----\n"), "PEM formatted RSA key expects to have a matching footer");
    }

    unittest /* Output private key in ascii, password protected */
    {
        import std.algorithm:startsWith, endsWith;
        auto key = new RsaKey(RsaKeyConfig(512));
        string str = key.toPEM("secret-password");
        assert(startsWith(str, "-----BEGIN RSA PRIVATE KEY-----", ), "PEM formatted RSA key expects to have a matching header");
        assert(endsWith(str, "-----END RSA PRIVATE KEY-----\n"), "PEM formatted RSA key expects to have a matching footer");
    }

    /**
     * Return the raw contained type when using with C API.
     */
    RSA* c_type()
    {
        return rsaKey;
    }
}
