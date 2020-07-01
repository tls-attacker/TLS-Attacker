/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

public enum CcaCertificateKeyType {
    RSA("rsa"),
    DH( "dh"),
    DSA("dsa"),
    ECDH("ecdh"),
    ECDSA("ecdsa"),
    KEA("kea");

    private String javaName;

    CcaCertificateKeyType(String javaName) {
        this.javaName = javaName;
    }

    public static CcaCertificateKeyType fromJavaName(String name) {
        for (CcaCertificateKeyType ccaCertificateKeyType : values()) {
            if (ccaCertificateKeyType.getJavaName().equals(name)) {
                return ccaCertificateKeyType;
            }
        }
        return null;
    }

    public String getJavaName() {
        return javaName;
    }


}
