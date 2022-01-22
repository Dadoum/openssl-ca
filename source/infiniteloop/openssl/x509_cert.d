module infiniteloop.openssl.x509_cert;

import core.stdc.string:strlen;
import core.stdc.time:time_t;
import std.array:byPair;
import std.conv:to;
import std.exception:enforce;
import std.string:toStringz;

/* External modules imports */
import deimos.openssl.x509;
import deimos.openssl.x509v3;
import deimos.openssl.pem;
import deimos.openssl.asn1;

/* Module-local imports */
import infiniteloop.openssl.bio;
import infiniteloop.openssl.error;
import infiniteloop.openssl.evp;
import infiniteloop.openssl.password;
import infiniteloop.openssl.x509_name;
import infiniteloop.openssl.x509v3_config;


X509Certificate newX509Certificate(const string[string] subjectName, const string[string] issuerName,
         ulong validNoOfDays, long serialNumber, EVPKey certificateKey, EVPKey signKey,
         const string[string] extensions = null, X509Certificate issuer = null)
{
    auto cert = new X509Certificate();
    cert.setSubjectName(subjectName);
    cert.setIssuerName(issuerName);
    cert.setValidityTime(to!int(validNoOfDays));
    cert.setSerialNumber(serialNumber);
    cert.setPublicKey(certificateKey);
    if (extensions.length)
    {
        cert.setVersion(2 /* = v3 */);
        cert.setV3ExtensionConfig(extensions, issuer);
    }
    cert.sign(signKey);
    return cert;
}

 /**
 * Wrapper for C struct 'X509' certificate.
 *
 * Reference:
 * https://github.com/openssl/openssl/blob/OpenSSL_1_1_0-stable/apps/req.c
 */
class X509Certificate
{
    private X509* certificate;

    this()
    {
        certificate = X509_new();
    }

    /**
     * Read in an existing PEM formatted certificate from string.
     */
    this(const string pemFormattedCertificate, const string password = "")
    {
        auto bio = new Bio(
            (BIO* mem) => null != PEM_read_bio_X509(mem, &certificate, &passwordCallbackWrapper,
                                        cast(void*)toStringz(password))
        );
        bio.fromStr(pemFormattedCertificate);
    }

    unittest /* Read an existing valid certificate from PEM formatted string */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;
        auto cert = new X509Certificate();
        cert.setPublicKey(key);
        cert.setValidityTime(375);
        cert.sign(key);
        assertNotThrown!OpenSSLError(
            new X509Certificate(cert.toPEM()),  "Expects to create a certificate successfully from a PEM formatted string"
        );
    }

    ~this()
    {
        X509_free(certificate);
    }

    /**
     * Return the raw contained type when using with C API.
     */
    X509* c_type()
    {
        return certificate;
    }

    void setPublicKey(EVPKey key)
    {
        enforce!OpenSSLError(
            1 == X509_set_pubkey(certificate, key.c_type()), "Failed to set public key on Certificate"
        );
    }

    unittest /* Set public key */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;
        auto cert = new X509Certificate();
        assertNotThrown!OpenSSLError(
            cert.setPublicKey(key), "Expects to successfully set certificate public key"
        );
    }

    EVPKey getPublicKey() const
    {
        auto pkey = X509_get0_pubkey(certificate);
        return new EVPKey(pkey);
    }

    unittest /* Get public key */
    {
        import infiniteloop.openssl.stubs.rsa : key;

        auto cert = new X509Certificate();
        cert.setPublicKey(key);
        auto fetchedKey = cert.getPublicKey();
        // ***TODO*** how to assert??
    }

    void setSerialNumber(long serialNumber)
    {
        enforce!OpenSSLError(
            1 == ASN1_INTEGER_set(X509_get_serialNumber(certificate), serialNumber), "Failed to set serial number on Certificate"
        );
    }

    unittest /* Set serial number */
    {
        import std.exception:assertNotThrown;
        auto cert = new X509Certificate();
        assertNotThrown!OpenSSLError(
            cert.setSerialNumber(123), "Expects to successfully set a valid serial number"
        );
    }

    long getSerialNumber() const
    {
        auto serialNoRaw = X509_get0_serialNumber(certificate);
        return ASN1_INTEGER_get(serialNoRaw); // Use "ASN1_INTEGER_get_int64" when openssl api for asn1 is uplifted to 1.1.0h.
    }

    unittest /* Get serial number */
    {
        long serialNo = 123;
        auto cert = new X509Certificate();
        cert.setSerialNumber(serialNo);
        long receivedSerialNo = cert.getSerialNumber();
        assert(serialNo == receivedSerialNo, "Expects to get same serial number on certificate as previously assigned");
    }

    void setValidityTime(int noOfDays)
    {
        time_t *timestamp = null; /* Use current timestamp */
        enforce!OpenSSLError(
            null != X509_time_adj(X509_get_notBefore(certificate), 0 /* = Offset from timestamp */, timestamp), "Failed to set validity time notBefore on Certificate"
        );
        enforce!OpenSSLError(
            null != X509_time_adj_ex(X509_get_notAfter(certificate), noOfDays, 0 /* seconds */, timestamp), "Failed to set validity time notAfter on Certificate"
        );
    }

    unittest /* Set validity time (in days) */
    {
        import std.exception:assertNotThrown;
        auto cert = new X509Certificate();
        assertNotThrown!OpenSSLError(
            cert.setValidityTime(365 /*days*/), "Expects to set a valid validity time on certificate successfully"
        );
    }

    void setVersion(int versionNumber)
    {
        enforce!OpenSSLError(
            1 == X509_set_version(certificate, versionNumber), "Failed to set version on Certificate"
        );
    }

    unittest /* Set version */
    {
        import std.exception:assertNotThrown;
        auto cert = new X509Certificate();
        assertNotThrown!OpenSSLError(
            cert.setVersion(2 /* = v3*/), "Expects to set a valid version on certificate successfully"
        );
    }

    void setIssuerName(const string[string] subject)
    {
        auto name = newX509Name(subject);
        X509_set_issuer_name(certificate, name.c_type());
    }

    unittest /* Set certificate issuer name */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.x509_subj:stringFormattedSubject;
        auto cert = new X509Certificate();
        assertNotThrown!OpenSSLError(
            cert.setIssuerName(stringFormattedSubject), "Expects to successfully set a valid certifacte issuer name"
        );
    }

    const(string)[string] getIssuerName() const
    {
        auto name =  new X509Name(X509_get_issuer_name(certificate));
        return name.getNameEntries();
    }

    unittest /* Get certificate issuer name */
    {
        import infiniteloop.openssl.stubs.x509_subj:stringFormattedSubject;
        import std.algorithm.comparison:isPermutation;
        auto cert = new X509Certificate();
        cert.setIssuerName(stringFormattedSubject);
        auto receivedIssuerEntries = cert.getIssuerName();
        assert(isPermutation(stringFormattedSubject.keys, receivedIssuerEntries.keys), "Issuer name keys are not equal");
        assert(isPermutation(stringFormattedSubject.values, receivedIssuerEntries.values), "Issuer name values are not equal");
    }

    void setSubjectName(const string[string] subject)
    {
        auto name = newX509Name(subject);
        X509_set_subject_name(certificate, name.c_type());
    }

    private X509Name newX509Name(const string[string] subject) const
    {
        auto name = new X509Name();
        foreach (entry; subject.byPair())
        {
            name.addNameEntry(entry.key, entry.value);
        }
        return name;
    }

    unittest /* Set subject name  */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.x509_subj:stringFormattedSubject;
        auto cert = new X509Certificate();
        assertNotThrown!OpenSSLError(
            cert.setSubjectName(stringFormattedSubject), "Expects to successfully set a valid certificate subject name"
        );
    }

    const(string)[string] getSubjectName() const
    {
        auto name = new X509Name(X509_get_subject_name(certificate));
        return name.getNameEntries();
    }

    unittest /* Get subject name  */
    {
        import infiniteloop.openssl.stubs.x509_subj:stringFormattedSubject;
        import std.algorithm.comparison:isPermutation;
        auto cert = new X509Certificate();
        cert.setSubjectName(stringFormattedSubject);
        auto receivedSubject = cert.getSubjectName();
        assert(isPermutation(stringFormattedSubject.keys, receivedSubject.keys), "Subject name keys are not equal");
        assert(isPermutation(stringFormattedSubject.values, receivedSubject.values), "Subject name values are not equal");
    }

    void setV3ExtensionConfig(const string[string] extensionConfig, X509Certificate issuer = null)
    {
        // see more @ https://github.com/openssl/openssl/blob/master/apps/ca.c#L1695
        auto x509v3 = new X509v3Config(extensionConfig);
        x509v3.addConfiguration(
            (CONF* config, X509V3_CTX* ctx) {
                if (issuer)
                {
                    X509V3_set_ctx(ctx, issuer.c_type(), certificate, null, null, 0);
                }
                else
                {
                    X509V3_set_ctx(ctx, certificate /* using self as issuer */, certificate, null, null, 0);
                }
                return 1 == X509V3_EXT_add_nconf(config, ctx, "default" /* "section" in config-file */, certificate);
            }
        );
    }

    unittest /* Set valid certificate v3 extensions */
    {
        import infiniteloop.openssl.stubs.rsa:key;
        import std.exception:assertNotThrown;
        auto cert = new X509Certificate();
        cert.setPublicKey(key);
        string[string] extensions = [
            "subjectKeyIdentifier": "hash",
            "basicConstraints": "critical, CA:true",
            "authorityKeyIdentifier": "keyid:always,issuer"
        ];
        assertNotThrown!OpenSSLError(
            cert.setV3ExtensionConfig(extensions), "Expects to successfully set a valid configuration"
        );
    }

    unittest /* Set valid certificate v3 extensions, independently on config order */
    {
        import infiniteloop.openssl.stubs.rsa:key;
        import std.exception:assertNotThrown;
        auto cert = new X509Certificate();
        cert.setPublicKey(key);
        string[string] extensions = [
            "basicConstraints": "critical, CA:true",
            "authorityKeyIdentifier": "keyid:always,issuer",
            "subjectKeyIdentifier": "hash", /* Must be applied before the "authorityKeyIdentifier", else "unable to get issuer keyid" is thrown */
        ];
        assertNotThrown!OpenSSLError(
            cert.setV3ExtensionConfig(extensions), "Expects to successfully set a valid configuration, independent of configuration order"
        );
    }

    unittest /* Set not valid certificate v3 extensions */
    {
        import std.exception:assertThrown;
        auto cert = new X509Certificate();
        string[string] extensions = ["asd": "123"];
        assertThrown!OpenSSLError(
            cert.setV3ExtensionConfig(extensions), "Expects to fail set when config non-valid"
        );
    }

    void sign(EVPKey key, MessageDigest md = MessageDigest.SHA_256)
    {
        if (key.getKeyType() == KeyType.ED25519)
        {
            md = MessageDigest.NONE;  // MessageDigest must be null for elliptic curves.
        }
        enforce!OpenSSLError(
            0 != X509_sign(certificate, key.c_type(), getEvpMessageDigest(md)), "Failed to sign Certificate"
        );
    }

    unittest /* Sign certificate */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;
        auto cert = new X509Certificate();
        assertNotThrown!OpenSSLError(
            cert.sign(key), "Expects to sign the certificate successfully"
        );
    }

    bool validateCertificateKey(const EVPKey pkey) const
    {
        return 1 == X509_check_private_key(certificate, pkey.c_type_const());
    }

    unittest /* Validate valid certificate */
    {
        import infiniteloop.openssl.stubs.rsa:key;
        auto cert = new X509Certificate();
        cert.setPublicKey(key);
        cert.sign(key);
        bool res = cert.validateCertificateKey(key);
        assert(res == true, "Expects to succeed validate the valid certificate");
    }

    unittest /* Validate invalid certificate */
    {
        import infiniteloop.openssl.stubs.rsa:key, anotherKey;
        auto cert = new X509Certificate();
        cert.setPublicKey(anotherKey);
        cert.sign(key);
        bool res = cert.validateCertificateKey(key);
        assert(res == false, "Expects to fail validation since signing key and validation key are different");
    }

    const(string) toPEM()
    {
        auto bio = new Bio((BIO* mem) => 1 == PEM_write_bio_X509(mem, certificate));
        return bio.to!string;
    }

    unittest /* Get certificate in PEM-formatted string  */
    {
        import std.algorithm:startsWith, endsWith;
        auto cert = new X509Certificate();
        auto str = cert.toPEM();
        assert(startsWith(str, "-----BEGIN CERTIFICATE-----", ), "PEM formatted certificate expects to have a matching header");
        assert(endsWith(str, "-----END CERTIFICATE-----\n"), "PEM formatted certificate expects to have a matching footer");
    }
}
