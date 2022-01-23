module infiniteloop.openssl.bio;

import core.stdc.stdlib;
import core.stdc.string : strlen;
import std.conv : to;
import std.exception : enforce;
import std.string : toStringz;

/* External modules imports */
import deimos.openssl.bio;

/* Module-local imports */
import infiniteloop.openssl.error : OpenSSLError;

class Bio
{
  alias IOConversionFcn = bool delegate(BIO* mem);

  private BIO* mem;
  private IOConversionFcn ioConversionFcn;

  this(IOConversionFcn ioConversionFcn)
  {
    this.mem = BIO_new(BIO_s_mem());
    this.ioConversionFcn = ioConversionFcn;
  }

  ~this()
  {
    BIO_free_all(mem);
  }

  override string toString()
  {
    enforce!OpenSSLError(
      ioConversionFcn(mem), "Conversion to string using ioConversionFcn failed"
    );
    return bioToString(mem);
  }

  unittest  /* Convert to string when ioConversionFcn reports success */
  {
    import std.exception : assertNotThrown;

    auto bio = new Bio(
      (BIO* mem) => true
    );
    assertNotThrown!OpenSSLError(
      bio.to!string, "Conversion from bio to string expects to succeed"
    );
  }

  unittest  /*  Convert to string when ioConversionFcn reports unsuccessful */
  {
    import std.exception : assertThrown;

    auto bio = new Bio(
      (BIO* mem) => false
    );
    assertThrown!OpenSSLError(
      bio.to!string, "Conversion from bio to string expects to fail"
    );
  }

  void fromStr(string content)
  {
    auto c_str = toStringz(content);
    enforce!OpenSSLError(
      0 < BIO_write(mem, c_str, cast(int) strlen(c_str)), "Conversion from string to bio failed"
    );
    enforce!OpenSSLError(
      ioConversionFcn(mem), "Conversion to string using ioConversionFcn failed"
    );
  }

  unittest  /* Convert to bio from string using ioConversionFcn reports success */
  {
    import std.exception : assertNotThrown;

    auto bio = new Bio(
      (BIO* mem) => true
    );
    assertNotThrown!OpenSSLError(
      bio.fromStr("any"), "Conversion from string to bio expects to succeed"
    );
  }

  unittest  /* Convert to bio from string using ioConversionFcn reports unsuccessful */
  {
    import std.exception : assertThrown;

    auto bio = new Bio(
      (BIO* mem) => false
    );
    assertThrown!OpenSSLError(
      bio.fromStr("any"), "Conversion from string to bio expects to fail"
    );
  }
}

const(string) bioToString(BIO* mem) nothrow
{
  immutable int len = BIO_pending(mem);
  void* c_str = calloc(len +  /* Null-termination */ 1, char.sizeof);
  BIO_read(mem, c_str, len);
  auto str = to!string(cast(char*) c_str);
  free(c_str);
  return str;
}
