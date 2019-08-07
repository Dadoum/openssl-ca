module infiniteloop.openssl.x509_csr;

import std.array:byPair;
import std.exception:enforce;
import std.string:toStringz;

/* External modules imports */
import deimos.openssl.pem;
import deimos.openssl.x509;
import deimos.openssl.x509v3;

/* Module-local imports */
import infiniteloop.openssl.bio;
import infiniteloop.openssl.error;
import infiniteloop.openssl.evp;
import infiniteloop.openssl.password;
import infiniteloop.openssl.x509_name;
import infiniteloop.openssl.x509v3_config;


X509CertificateSigningRequest newX509CertificateSigningRequest(const string[string] subjectName, EVPKey key,
        string[string] extensions = null)
{
    auto req = new X509CertificateSigningRequest();
    req.setSubjectName(subjectName);
    if (extensions.length)
    {
        req.setVersion(2 /* = v3 */);
        req.setV3ExtensionConfig(extensions);
    }
    req.setPublicKey(key);
    req.sign(key);
    return req;
}

 /**
 * Wrapper for C struct 'X509_REQ' certificate signing request.
 *
 * Reference:
 * https://github.com/openssl/openssl/blob/OpenSSL_1_1_0-stable/apps/req.c
 */
class X509CertificateSigningRequest
{
    private X509_REQ* csr;

    this()
    {
        this.csr = X509_REQ_new();
    }

    /**
     * Read in an existing PEM formatted CSR from string.
     */
    this(const string pemFormattedCSR, const string password = "")
    {
        auto bio = new Bio(
            (BIO* mem) => null != PEM_read_bio_X509_REQ(mem, &csr, &passwordCallbackWrapper,
                                        cast(void*)toStringz(password))
        );
        bio.fromStr(pemFormattedCSR);
    }

    unittest /* Read an existing CSR from PEM formatted string */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;
        auto pkey = new EVPKey(key);
        auto csr = new X509CertificateSigningRequest();
        csr.setPublicKey(pkey);
        csr.sign(pkey);
        assertNotThrown!OpenSSLError(
            new X509CertificateSigningRequest(csr.toPEM()), "Expects to create a certificate signing request successfully from a PEM formatted string"
        );
    }

    ~this()
    {
        X509_REQ_free(csr);
    }

    /**
     * Return the raw contained type when using with C API.
     */
    X509_REQ* c_type()
    {
        return csr;
    }

    void setVersion(int versionNumber)
    {
        enforce!OpenSSLError(
            1 == X509_REQ_set_version(csr, versionNumber), "Failed to set version on Certificate Signing Request"
        );
    }

    unittest /* Set version */
    {
        import std.exception:assertNotThrown;
        auto csr = new X509CertificateSigningRequest();
        assertNotThrown!OpenSSLError(
            csr.setVersion(2 /* = v3*/), "Expects to set a valid version on Certificate Signing Request successfully"
        );
    }

    void setSubjectName(const string[string] subject)
    {
        auto name = newX509Name(subject);
        X509_REQ_set_subject_name(csr, name.c_type());
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

    unittest /* Set SubjectName */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.x509_subj:stringFormattedSubject;
        import std.algorithm.comparison:equal;

        auto csr = new X509CertificateSigningRequest();
        assertNotThrown!OpenSSLError(
            csr.setSubjectName(stringFormattedSubject), "Expects to set a valid subject name successfully"
        );
    }

    const(string)[string] getSubjectName() const
    {
        auto name = new X509Name(X509_REQ_get_subject_name(csr));
        return name.getNameEntries();
    }

    unittest /* Get SubjectName */
    {
        import infiniteloop.openssl.stubs.x509_subj:stringFormattedSubject;
        import std.algorithm.comparison:isPermutation;

        auto csr = new X509CertificateSigningRequest();
        csr.setSubjectName(stringFormattedSubject);
        auto receivedSubject = csr.getSubjectName();
        assert(isPermutation(stringFormattedSubject.keys, receivedSubject.keys), "Subject name keys are not equal");
        assert(isPermutation(stringFormattedSubject.values, receivedSubject.values), "Subject name values are not equal");
    }

    void setPublicKey(EVPKey key)
    {
        enforce!OpenSSLError(
            1 == X509_REQ_set_pubkey(csr, key.c_type()), "Failed to set public key on Certificate Signing Request"
        );
    }

    unittest /* Set public key */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;

        auto pkey = new EVPKey(key);
        auto csr = new X509CertificateSigningRequest();
        assertNotThrown!OpenSSLError(
            csr.setPublicKey(pkey), "Expect to successfully set the public key of the certificate signing request"
        );
    }

    EVPKey getPublicKey()
    {
        auto pkey = X509_REQ_get0_pubkey(csr);
        return new EVPKey(pkey);
    }

    unittest /* Get public key */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa : key;

        auto pkey = new EVPKey(key);
        auto csr = new X509CertificateSigningRequest();
        csr.setPublicKey(pkey);
        assertNotThrown!OpenSSLError(
            csr.getPublicKey(), "Expect to successfully return the public key of the certificate signing request"
        );
    }

    void setV3ExtensionConfig(const string[string] extensionConfig)
    {
        auto x509v3 = new X509v3Config(extensionConfig);
        x509v3.addConfiguration(
            (CONF* config, X509V3_CTX* ctx) {
                // see more @ https://github.com/openssl/openssl/blob/master/apps/req.c#L821
                X509V3_set_ctx(ctx, null, null, csr, null, 0);
                return 1 == X509V3_EXT_REQ_add_nconf(config, ctx, "default" /* "section" in config-file */, csr);
            }
        );
    }

    unittest /* Set valid CSR V3 extensions */
    {
        import std.exception:assertNotThrown;
        auto csr = new X509CertificateSigningRequest();
        string[string] extensions = [
            "basicConstraints": "critical, CA:true",
            "subjectKeyIdentifier": "hash"
        ];
        assertNotThrown!OpenSSLError(
            csr.setV3ExtensionConfig(extensions), "Expects success to set a valid v3 extensions configuration"
        );
    }

    unittest /* Set not valid CSR V3 extensions */
    {
        import std.exception:assertThrown;
        auto csr = new X509CertificateSigningRequest();
        string[string] extensions = ["asd": "123"];
        assertThrown!OpenSSLError(
            csr.setV3ExtensionConfig(extensions), "Expects failure to set a non-valid v3 extensions configuration"
        );
    }

    void sign(EVPKey key, MessageDigest md = MessageDigest.SHA_256)
    {
        enforce!OpenSSLError(
            0 != X509_REQ_sign(csr, key.c_type(), getEvpMessageDigest(md)), "Failed to sign Certificate Signing Request"
        );
    }

    unittest /* Sign CSR */
    {
        import std.exception:assertNotThrown;
        import infiniteloop.openssl.stubs.rsa:key;

        auto pkey = new EVPKey(key);
        auto csr = new X509CertificateSigningRequest();
        assertNotThrown!OpenSSLError(
            csr.sign(pkey), "Expects to sign certificate with success"
        );
    }

    bool validateSignature()
    {
        auto publicKey = X509_REQ_get0_pubkey(csr);
        return 1 == X509_REQ_verify(csr, publicKey);
    }

    unittest /* Validate valid signature of CSR */
    {
        import infiniteloop.openssl.stubs.rsa:key;

        auto pkey = new EVPKey(key);
        auto csr = new X509CertificateSigningRequest();
        csr.setPublicKey(pkey);
        csr.sign(pkey);
        bool res = csr.validateSignature();
        assert(res == true, "Expecteded to succeed on Certificate Signing Request validation");
    }

    unittest /* Validate invalid signature of CSR */
    {
        import infiniteloop.openssl.stubs.rsa:key, anotherKey;

        auto csr = new X509CertificateSigningRequest();
        csr.setPublicKey(new EVPKey(key));
        csr.sign(new EVPKey(anotherKey));
        bool res = csr.validateSignature();
        assert(res == false, "Expecteded to fail on Certificate Signing Request validation");
    }

    string toPEM()
    {
        auto bio = new Bio(
            (BIO* mem) => 1 == PEM_write_bio_X509_REQ(mem, csr)
        );
        return bio.toString();
    }

    unittest /* Get CSR in PEM-formatted string */
    {
        import std.algorithm:startsWith, endsWith;

        auto csr = new X509CertificateSigningRequest();
        auto pem = csr.toPEM();
        assert(startsWith(pem, "-----BEGIN CERTIFICATE REQUEST-----", ), "PEM formatted certificate signing request expects to have a matching header");
        assert(endsWith(pem, "-----END CERTIFICATE REQUEST-----\n"), "PEM formatted certificate signing request expects to have a matching footer");
    }
}
