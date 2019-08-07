module infiniteloop.openssl.password;

import core.stdc.string;
import std.string:toStringz;
import std.conv;

/* External modules imports */
import deimos.openssl.evp;
import deimos.openssl.pem;

/* Module-local imports */
import infiniteloop.openssl.evp;

/**
 * Class representing a user password.
 */
class Password
{
    private ubyte* password = null;
    private int length = 0;
    private const(EVP_CIPHER)* chiper = null;

    this()
    {
        /* Using default values */
    }

    this(const string password, Chiper chiper = Chiper.AES_256_CBC)
    {
        auto c_password = toStringz(password);
        this.password = cast(ubyte*)c_password;
        this.length = to!int(strlen(c_password));
        this.chiper = getEvpChiper(chiper);
    }

    ubyte* getPassword()
    {
        return password;
    }

    const(EVP_CIPHER)* getChiper() const
    {
        return chiper;
    }

    int getLength() const
    {
        return length;
    }
}


/**
 * Callback function used in OpenSSL C API.
 */
extern (C) alias PasswordCallback = int function(char *buf, int max_size, int rwflag, void *cb_data);
extern (C) int passwordCallbackWrapper(char *buf, int max_size, int rwflag, void *cb_data)
{
    auto password = cast(char*)cb_data;
    auto size = strlen(password);
    if (size < max_size)
    {
        memcpy(buf, password, size);
    }
    else
    {
        size = 0;
    }
    return size.to!int;
}
