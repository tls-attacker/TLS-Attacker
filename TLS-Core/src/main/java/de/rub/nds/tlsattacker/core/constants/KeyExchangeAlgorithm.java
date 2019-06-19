/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum KeyExchangeAlgorithm {

    NULL,
    DHE_DSS,
    DHE_RSA,
    DHE_PSK,
    DH_ANON,
    RSA,
    PSK_RSA,
    DH_DSS,
    DH_RSA,
    KRB5,
    SRP_SHA_DSS,
    SRP_SHA_RSA,
    SRP_SHA,
    PSK,
    ECDH_RSA,
    ECDH_ANON,
    ECDH_ECDSA,
    ECDHE_ECDSA,
    ECDHE_RSA,
    ECDHE_PSK,
    VKO_GOST01,
    VKO_GOST12,
    FORTEZZA_KEA,
    ECMQV_ECDSA,
    ECMQV_ECNRA,
    ECDH_ECNRA,
    CECPQ1_ECDSA,
    ECCPWD;

    public CertificateKeyType getRequiredCertPublicKeyType() {
        switch (this) {
            case DHE_DSS:
            case SRP_SHA_DSS:
                return CertificateKeyType.DSS;
            case ECDHE_RSA:
            case PSK_RSA:
            case RSA:
            case DHE_RSA:
            case SRP_SHA_RSA:
                return CertificateKeyType.RSA;
            case DH_DSS:
            case DH_RSA:
                return CertificateKeyType.DH;
            case ECDH_ECNRA:
            case ECDHE_ECDSA:
            case ECDH_ECDSA:
            case ECMQV_ECDSA:
            case CECPQ1_ECDSA:
            case ECDH_RSA:
                return CertificateKeyType.ECDSA;
            case NULL:
            case DHE_PSK:
            case DH_ANON:
            case ECDHE_PSK:
            case ECDH_ANON:
            case PSK:
            case SRP_SHA:
            case ECCPWD:
                return CertificateKeyType.NONE;
            case VKO_GOST01:
                return CertificateKeyType.GOST01;
            case VKO_GOST12:
                return CertificateKeyType.GOST12;

            case ECMQV_ECNRA:
            case FORTEZZA_KEA:
            case KRB5:

            default:
                throw new UnsupportedOperationException("Currently unsupported");
        }
    }

    public boolean isKeyExchangeRsa() {
        return this.equals(this.RSA);
    }

    public boolean isKeyExchangeDh() {
        switch (this) {
            case DHE_DSS:
            case DHE_PSK:
            case DHE_RSA:
            case DH_ANON:
            case DH_DSS:
            case DH_RSA:
                return true;
            default:
                return false;
        }
    }

    public boolean isKeyExchangeEcdh() {
        switch (this) {
            case ECDHE_ECDSA:
            case ECDHE_PSK:
            case ECDHE_RSA:
            case ECDH_ANON:
            case ECDH_ECDSA:
            case ECDH_ECNRA:
            case ECDH_RSA:
                return true;
            default:
                return false;
        }
    }

    public boolean isEC() {
        return this.name().contains("EC");
    }

    public boolean isAnon() {
        return this.name().contains("ANON");
    }
}
