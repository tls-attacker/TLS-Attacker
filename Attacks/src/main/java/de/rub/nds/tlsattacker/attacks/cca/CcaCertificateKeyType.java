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
    RSA("rsa", "1.2.840.113549.1.1.1"),
    DH( "dh", "1.2.840.113549.1.3.1"),
    DSA("dsa", "1.2.840.10040.4.1"),
    ECDSA("ecdsa", "1.2.840.10045.2.1");

    private String javaName;
    private String oid;

    CcaCertificateKeyType(String javaName, String oid) {
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

    public static CcaCertificateKeyType fromOid(String oid) {
        for (CcaCertificateKeyType ccaCertificateKeyType : values()) {
            if (ccaCertificateKeyType.getOid().equals(oid)) {
                return ccaCertificateKeyType;
            }
        }
        return null;
    }
    
    public String getJavaName() {
        return javaName;
    }

    public String getOid() { return oid; }
}
