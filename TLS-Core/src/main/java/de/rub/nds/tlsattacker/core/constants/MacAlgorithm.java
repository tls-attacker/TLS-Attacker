/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;


public enum MacAlgorithm {

    NULL("null"),
    AEAD("null"),
    SSLMAC_MD5("SslMacMD5"), // supported by SunJCE
    SSLMAC_SHA1("SslMacSHA1"), // supported by SunJCE
    HMAC_MD5("HmacMD5"),
    HMAC_SHA1("HmacSHA1"),
    HMAC_SHA256("HmacSHA256"),
    HMAC_SHA384("HmacSHA384"),
    HMAC_SHA512("HmacSHA512"),
    IMIT_GOST28147("IMIT_GOST28147"), // java name not verified
    HMAC_GOSTR3411("HmacGOSTR3411");// java name not verified
    MacAlgorithm(String javaName) {
        this.javaName = javaName;
    }

    private final String javaName;

    public String getJavaName() {
        return javaName;
    }
}
