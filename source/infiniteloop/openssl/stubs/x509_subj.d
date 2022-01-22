module infiniteloop.openssl.stubs.x509_subj;


static immutable string[string] stringFormattedSubject;

shared static this()
{
    stringFormattedSubject =  [
        "C": "SE",
        "ST": "Gothenburg",
        "O": "World Wide Web Inc.",
        "OU": "World Wide Web Inc. Certificate Authority",
        "CN": "www.example.com"
    ];
}
