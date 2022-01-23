module infiniteloop.openssl.x509_name;

import std.conv : to;
import std.exception : enforce;
import std.format;
import std.string : toStringz;

/* External module imports */
import deimos.openssl.x509;

/* Local imports */
import infiniteloop.openssl.error;

class X509Name
{
  private X509_NAME* name;

  this()
  {
    this.name = X509_NAME_new();
  }

  this(X509_NAME* name)
  {
    this.name = X509_NAME_dup(name);
  }

  ~this()
  {
    X509_NAME_free(name);
  }

  /**
   * Return the raw contained type when using with C API.
   */
  X509_NAME* c_type()
  {
    return name;
  }

  void addNameEntry(const string key, const string value)
  {
    enum strlen = -1; /* String length (calculate internally) */
    enum location = -1; /* Append entry (no index specified) */
    enum set = 0; /* Add new entry */
    enforce!OpenSSLError(
      1 == X509_NAME_add_entry_by_txt(this.name, toStringz(key), MBSTRING_ASC, cast(ubyte*) toStringz(
        value),
        strlen, location, set), format("Failed to add name entry %s = %s", key, value)
    );
  }

  unittest  /* Add name entry */
  {
    import std.exception : assertNotThrown;

    auto name = new X509Name();
    assertNotThrown!OpenSSLError(
      name.addNameEntry("CN", "Hello, world wide web!"), "Add valid name entry is expected to succeed"
    );
  }

  unittest  /* Add invalid name entry */
  {
    import std.exception : assertThrown;

    auto name = new X509Name();
    assertThrown!OpenSSLError(
      name.addNameEntry("asd", "123"), "Get non-existing name entry is expected to fail"
    );
  }

  const(string)[string] getNameEntries() const
  {
    import std.stdio;

    string[string] nameEntries;
    int noOfItems = X509_NAME_entry_count(name);
    foreach (i; 0 .. noOfItems)
    {
      auto entry = X509_NAME_get_entry(name, i);
      string key = getKey(entry);
      string value = getValue(entry);
      nameEntries[key] = value;
    }
    return nameEntries;
  }

  unittest  /* Get name entries */
  {
    import std.exception : assertNotThrown;

    auto name = new X509Name();
    name.addNameEntry("CN", "Hello, world wide web!");
    assertNotThrown!OpenSSLError(
      name.getNameEntries(), "Get existing name entries is expected to succeed"
    );
  }

  private const(string) getValue(const X509_NAME_ENTRY* nameEntry) const
  {
    char* raw;
    ASN1_STRING* fieldName = X509_NAME_ENTRY_get_data(nameEntry);
    int res = ASN1_STRING_to_UTF8(&raw, fieldName);
    const string value = to!string(raw);
    OPENSSL_free(raw);
    if (res < 0)
    {
      throw new OpenSSLError("Could not read value of name entry");
    }
    return value;
  }

  private const(string) getKey(const X509_NAME_ENTRY* nameEntry) const
  {
    ASN1_OBJECT* fieldValue = X509_NAME_ENTRY_get_object(nameEntry);
    int nid = OBJ_obj2nid(fieldValue);
    return to!string(OBJ_nid2sn(nid)); /* return short name "sn" */
  }
}
