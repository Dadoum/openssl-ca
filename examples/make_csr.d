#!/usr/bin/env dub
/+ dub.sdl:
	name "openssl-ca-example"
    dependency "openssl-ca" version="1.0.0"
+/

import std.stdio;

import infiniteloop.openssl;

void main()
{
    writeln("Creating a PEM formatted certificate signing request (and a new RSA key)...");
    immutable string[string] subject = [
        "C":  "SE", 
        "ST": "Gothenburg", 
        "O":  "InfiniteLoop Inc.", 
        "OU": "InfiniteLoop Inc. Certificate Authority", 
        "CN": "www.infiniteloop.sh"
    ];
    auto key = new RsaKey(RsaKeyConfig(512));
    auto csr = newX509CertificateSigningRequest(
        subject, new EVPKey(key)
    );
    writefln("PEM formatted certificate signing request:\n%s", csr.toPEM());
    writefln("PEM formatted RSA Key:\n%s", key.toPEM());
}