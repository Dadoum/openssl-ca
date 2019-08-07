module infiniteloop.openssl.x509v3_config;

import std.algorithm:sort;
import std.array;
import std.format;
import std.exception:enforce;
import std.string:toStringz;

/* External modules imports */
import deimos.openssl.conf;
import deimos.openssl.err;
import deimos.openssl.x509v3;

/* Module-local imports */
import infiniteloop.openssl.bio;
import infiniteloop.openssl.error;


private struct SortableConfiguration
{
    string key;
    string value;
    int nid;

    int opCmp(ref const SortableConfiguration rhs) const
    {
        return nid - rhs.nid;
    }
}


/**
 * see more @ "man x509v3_config" or
 * https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
 */
class X509v3Config
{
    alias ConfigurationAdderFcn = bool delegate(CONF* config, X509V3_CTX* ctx);

    private CONF* config;

    this(const string[string] conf)
    {
        this.config = NCONF_new(null);
        loadConfigFromString(formatConfig(conf));
    }

    private const(string) formatConfig(const string[string] conf) const
    {
        string formattedConfigurations;
        auto sortableConfig = toSortableConf(conf);
        foreach (const ref SortableConfiguration item; sortableConfig.sort())
        {
            formattedConfigurations ~= item.key ~ '=' ~ item.value ~ '\n';
        }
        return formattedConfigurations;
    }

    private SortableConfiguration[] toSortableConf(const string[string] conf) const
    {
        SortableConfiguration[] sortableConfig;
        foreach (key, value; conf.byPair())
        {
            sortableConfig ~= SortableConfiguration(key, value, OBJ_txt2nid(toStringz(key)));
        }
        return sortableConfig;
    }

    private void loadConfigFromString(const string conf)
    {
        long errorline = -1;
        auto bio = new Bio(
            (BIO* mem) => 1 == NCONF_load_bio(config, mem, &errorline)
        );
        bio.fromStr(conf);
        enforce!OpenSSLError(
            errorline == -1, format("Error on row %d in configuration", errorline)
        );
    }

    ~this()
    {
        NCONF_free(config);
    }

    /**
     * Return the raw contained type when using with C API.
     */
    CONF* c_type()
    {
        return config;
    }

    void addConfiguration(ConfigurationAdderFcn configurationAdder)
    {
        X509V3_CTX ctx;
        X509V3_set_nconf(&ctx, config);
        enforce!OpenSSLError(
            configurationAdder(config, &ctx), "Failed to add x509 v3 configuration"
        );
    }
}
