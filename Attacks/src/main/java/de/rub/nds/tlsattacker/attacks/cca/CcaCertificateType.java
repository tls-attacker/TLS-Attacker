/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

public enum CcaCertificateType {
    CLIENT_INPUT("The certificate provided to the CLI switch", true, false),
    EMPTY("An empty certificate.", false, false),
    ROOTv3_CAv3_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA.",
            false,
            true),
    ROOTv3_CAv3_LEAFv1_nLEAF_RSAv3(
            "RSA Leaf Certificate generated with an intermediate Certificate that is v1 (actually not a CA). "
                    + "Root CA is v3.",
            false,
            true),
    ROOTv3_CAv3_LEAFv2_nLEAF_RSAv3(
            "RSA Leaf Certificate generated with an intermediate Certificate that is v2 (actually not a CA). "
                    + "Root CA is v3.",
            false,
            true),
    ROOTv1_CAv3_LEAFv1_nLEAF_RSAv3(
            "RSA Leaf Certificate generated with an intermediate Certificate that is v1 (actually not a CA). "
                    + "Root CA is v1.",
            false,
            true),
    ROOTv1_CAv3_LEAFv2_nLEAF_RSAv3(
            "RSA Leaf Certificate generated with an intermediate Certificate that is v2 (actually not a CA). "
                    + "Root CA is v1.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_expired(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The Leaf certificate is already expired.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_NotYetValid(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The Leaf certificate is only valid in the future.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_UnknownCritExt(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The Leaf certificate contains and unknown critical extension.",
            false,
            true),
    ROOTv3_CAv3_ZeroPathLen_CAv3_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The first intermediate CA certificate specifies a PathLen of zero.",
            false,
            true),
    ROOTv3_CAv3_NoBasicConstraints_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate has no BasicConstraintsExtension.",
            false,
            true),
    ROOTv3_CAv3_CaFalse_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate has the CA flag set to false.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv2(
            "RSA Leaf certificate v2 generated based on the provided (root-)CA certificate with one intermediate CA.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv1(
            "RSA Leaf certificate v1 generated based on the provided (root-)CA certificate with one intermediate CA.",
            false,
            true),
    ROOTv3_CAv3_KeyUsageNothing_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate specifies a KeyUsage of nothing.",
            false,
            true),
    ROOTv3_CAv3_KeyUsageDigitalSignatures_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate specifies a KeyUsage for digital signatures only.",
            false,
            true),
    ROOTv3_CAv3_NoKeyUsage_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate specifies no KeyUsage extension.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3__RDN_difference(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate and the leaf certificate use different ways to specify the same subject/issuer. "
                    + "A faulty implementation might use some abstruse string comparison to determine if issuer==subject which"
                    + " could succeed in this case.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_extendedKeyUsageServerAuth(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The leaf certificates extended key usage extensions specifies server authentication only.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_extendedKeyUsageCodeSign(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The leaf certificates extended key usage extensions specifies code signing only.",
            false,
            true),
    ROOTv3_CAv3_NameConstraints_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate.",
            false,
            true),
    // Postponed due to lacking implementations in ASN.1-Tool
    ROOTv3_debug("debugging", false, true);

    private String description;
    private Boolean requiresCertificate;
    private Boolean requiresCaCertAndKeys;

    CcaCertificateType(String description, Boolean requiresCertificate, Boolean requiresCaCertAndKeys) {
        this.description = description;
        this.requiresCertificate = requiresCertificate;
        this.requiresCaCertAndKeys = requiresCaCertAndKeys;
    }

    public String getDescription() {
        return description;
    }

    public Boolean getRequiresCertificate() {
        return this.requiresCertificate;
    }

    public Boolean getRequiresCaCertAndKeys() {
        return this.requiresCaCertAndKeys;
    }
}
