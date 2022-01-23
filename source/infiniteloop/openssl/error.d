module infiniteloop.openssl.error;

import core.stdc.stdlib;
import core.stdc.string : strlen;
import std.conv : to;

/* External modules imports */
import deimos.openssl.bio;
import deimos.openssl.err : ERR_print_errors;

/* Module-local imports */
import infiniteloop.openssl.bio : bioToString;

/**
 * Exception which prints out errors from OpenSSL C API Error stack.
 */
class OpenSSLError : Exception
{
  this(string msg, string file = __FILE__, size_t line = __LINE__)
  {
    super(msg ~ "\n" ~ getOpensslError(), file, line);
  }
}

private const(string) getOpensslError() nothrow
{
  auto mem = BIO_new(BIO_s_mem());
  ERR_print_errors(mem);
  auto errorStack = bioToString(mem);
  BIO_free_all(mem);
  return errorStack;
}
