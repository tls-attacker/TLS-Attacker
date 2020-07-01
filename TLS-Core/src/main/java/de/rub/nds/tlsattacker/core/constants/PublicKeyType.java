package de.rub.nds.tlsattacker.core.constants;

public enum PublicKeyType {
    DH("1.2.840.113549.1.3.1"),
    RSA("1.2.840.113549.1.1.1"),
    DSS("1.2.840.10040.4.1"),
    ECDSA("1.2.840.10045.2.1");

    private String oid;

    PublicKeyType(String oid) { this.oid = oid; }

    public static PublicKeyType fromOid(String oid) {
        for (PublicKeyType ccaCertificateKeyType : values()) {
            if (ccaCertificateKeyType.getOid().equals(oid)) {
                return ccaCertificateKeyType;
            }
        }
        return null;
    }

    public String getOid() {
        return oid;
    }
}
