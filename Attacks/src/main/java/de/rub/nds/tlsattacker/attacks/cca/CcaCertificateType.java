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
    ROOTv3_CAv3_LEAF_RSAv3_UnknownExt(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The Leaf certificate contains and unknown extension.",
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
    ROOTv3_CAv3_MalformedNameConstraints_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
                    + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate."
                    + "Additionally the NameConstraints extension uses implicit tagging where explicit is expected, hence "
                    + "presenting malformed ASN.1.",
            false,
            true),
    ROOTv3_CAv3_CAv3_PathLoop(
            "Path loop created by two CA certificates signing each other.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_CaTrue(
            "Chain of provided root CA, intermediate CA and a Leaf Cert that is declared a CA (BasicConstraints).",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_KeyUsageNothing(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
                    + "The leaf certificates key usage extensions allows no key usage at all.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_KeyUsageDigitalSignatures(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
                    + "The leaf certificates key usage extensions allows digitalSignatues only.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_AdditionalCertAfterChain(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
                    + "Additionally after the certificate chain is a self signed attacker certificate. This test case "
                    + "requires manual verification of which entity is authenticated on the server.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_SelfSigned(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
                    + "The leaf certificate points to the intermediate CA but is actually self signed.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_EmptySigned(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
                    + "The leaf certificate points to the intermediate CA but isn't signed at all. (Empty signatureValue)",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_AdditionalCertAfterLeaf(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
                    + "Additionally after the leaf certificate is a self signed attacker certificate. This test case "
                    + "requires manual verification of which entity is authenticated on the server.",
            false,
            true),
    ROOTv3_CAv3_LEAF_RSAv3_CertPolicy(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
                    + "The leaf certificate and CA certificate has a certificate policy extension with the any value pointing to an URL.",
            false,
            true),
//    ROOTv3_CAv3_LEAF_RSAv3_NullSigned(
//            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
//                    + "The leaf certificate points to the intermediate CA but isn't signed at all. (Null Signature)",
//            false,
//            true),
//    Removed because cert.isEmpty() returns true if NullTag is used (Note, this only happens after the server received the certificate)
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
