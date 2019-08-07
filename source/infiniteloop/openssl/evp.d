module infiniteloop.openssl.evp;

import std.conv;
import std.exception:enforce;
import std.string:toStringz;

/* External modules imports */
import deimos.openssl.evp;
import deimos.openssl.pem;

/* Module-local imports */
import infiniteloop.openssl.bio;
import infiniteloop.openssl.error;
import infiniteloop.openssl.password;
import infiniteloop.openssl.rsa;


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
    }
}

/**
 * Wrapper for C struct 'EVP_PKEY' which represents an algorithm-independent cryptographic key.
 */
class EVPKey
{
    private EVP_PKEY *key;
    private bool hasOwnership = true;  // Remove when deimos.openssl.evp is uplifted 1.1.0h

public:

    this()
    {
        key = EVP_PKEY_new();
    }

    this(RsaKey rsaKey)
    {
        key = EVP_PKEY_new();
        enforce!OpenSSLError(
            1 == EVP_PKEY_set1_RSA(key, rsaKey.c_type()), "Failed to create EVP Key from RSA Key"
        );
    }

    unittest /* Create EVP key from an RSA key */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;
        auto evpKey = new EVPKey(key);
        assertNotThrown!OpenSSLError(
            evpKey.toPEM(), "Expects to successfully convert EVP key to PEM formatted string"
        );
    }

/*
    this(EVP_PKEY *key)
    {
        EVP_PKEY_up_ref(key);  // doesn't exist. "deimos.openssl.evp" not uplifted to ver 1.1.0h.
        this.key = key
    }

    this(EVP_PKEY *key)
    {
        this.key = EVP_PKEY_new();
        EVP_PKEY_copy_parameters(this.key, key);  // segfaults. "deimos.openssl.evp" not uplifted to ver 1.1.0h.
    }

    this(EVP_PKEY *key)
    {
        this.key = EVP_PKEY_new();
        auto ctx = EVP_PKEY_CTX_new();
        this.key = EVP_PKEY_CTX_get0_pkey(ctx);  // segfaults. "deimos.openssl.evp" not uplifted to ver 1.1.0h.
        EVP_PKEY_CTX_free(ctx);
    }
*/

    this(EVP_PKEY *key)
    {
        this.key = key;
        hasOwnership = false;
    }

    /**
     * Read in an existing RSA key from string.
     */
    this(const string pemFormattedKey, const string password = "")
    {
        auto bio = new Bio(
            (BIO* mem) => null != PEM_read_bio_PrivateKey(mem, &key, &passwordCallbackWrapper, cast(void*)toStringz(password))
        );
        bio.fromStr(pemFormattedKey);
    }

    unittest /* Read an existing EVP key (RSA) from string */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;
        auto evpKey = new EVPKey(key);
        assertNotThrown!OpenSSLError(
            new EVPKey(evpKey.toPEM()), "EVP key is expected to successfully be created from a PEM formatted string"
        );
    }

    unittest /* Read an existing password-protected EVP key (RSA) from string */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;
        string password = "secret";
        auto evpKey = new EVPKey(key);
        assertNotThrown!OpenSSLError(
            new EVPKey(evpKey.toPEM(password), password), "Password protected EVP key is expected to successfully be created from a PEM formatted string"
        );
    }

    unittest /* Read an existing password-protected EVP key (RSA) from string, with incorrect password */
    {
        import infiniteloop.openssl.stubs.rsa:key;
        import infiniteloop.openssl.error:OpenSSLError;
        import std.exception:assertThrown;
        auto evpKey = new EVPKey(key);
        auto evpKeyEncoded = evpKey.toPEM("secret");
        assertThrown!OpenSSLError(
            new EVPKey(evpKeyEncoded, "faulty-password"), "Expects to fail reading EVP key with incorrect password"
        );
    }

    ~this()
    {
        if (hasOwnership)
        {
            EVP_PKEY_free(key);
        }
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

    unittest /* Output private key (RSA) in ascii */
    {
        import infiniteloop.openssl.stubs.rsa:key;
        import std.algorithm:startsWith, endsWith;
        auto evpKey = new EVPKey(key);
        string str = evpKey.toPEM();
        assert(startsWith(str, "-----BEGIN PRIVATE KEY-----", ), "PEM formatted EVP key expects to have a matching header");
        assert(endsWith(str, "-----END PRIVATE KEY-----\n"), "PEM formatted EVP key expects to have a matching footer");
    }

    unittest /* Output private key (RSA) in ascii, password protected */
    {
        import infiniteloop.openssl.stubs.rsa:key;
        import std.algorithm:startsWith, endsWith;
        auto evpKey = new EVPKey(key);
        string str = evpKey.toPEM("secret-password");
        assert(startsWith(str, "-----BEGIN ENCRYPTED PRIVATE KEY-----", ), "PEM formatted EVP key expects to have a matching header");
        assert(endsWith(str, "-----END ENCRYPTED PRIVATE KEY-----\n"), "PEM formatted EVP key expects to have a matching footer");
    }

    /**
     * Writes in PKCS#8
     */
    private /*const (ver >= 1.1.0h) */ const(string) toPEM(Password password)
    {
        auto bio = new Bio(
            (BIO* mem) => 1 == PEM_write_bio_PrivateKey(mem, key, password.getChiper(), password.getPassword(),
                                    password.getLength(), null /* password callback */, null /* callback data */ )
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
