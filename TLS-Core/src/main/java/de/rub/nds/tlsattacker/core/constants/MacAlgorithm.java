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

    NULL("null", 0, 0),
    AEAD("null", 0, 0),
    SSLMAC_MD5("SslMacMD5", 16, 16), // supported by SunJCE
    SSLMAC_SHA1("SslMacSHA1", 20, 20), // supported by SunJCE
    HMAC_MD5("HmacMD5", 16, 16),
    HMAC_SHA1("HmacSHA1", 20, 20),
    HMAC_SHA256("HmacSHA256", 32, 32),
    HMAC_SHA384("HmacSHA384", 48, 48),
    HMAC_SHA512("HmacSHA512", 64, 64),
    IMIT_GOST28147("GOST28147MAC", 4, 32),
    HMAC_GOSTR3411("HmacGOST3411", 32, 32),
    HMAC_GOSTR3411_2012_256("HmacGOST3411-2012-256", 32, 32);

    private final int size;
    private final int keySize;

    MacAlgorithm(String javaName, int size, int keySize) {
        this.javaName = javaName;
        this.size = size;
        this.keySize = keySize;
    }

    private final String javaName;

    public String getJavaName() {
        return javaName;
    }

    public int getSize() {
        return size;
    }

    public int getKeySize() {
        return keySize;
    }

}
