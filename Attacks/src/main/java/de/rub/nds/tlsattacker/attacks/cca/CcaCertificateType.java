/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.cca;

public enum CcaCertificateType {
    CLIENT_INPUT("The certificate provided to the CLI switch", true, false),
    EMPTY("An empty certificate.", false, false),
    ROOTv3_CAv3_LEAFv3_nLEAF_RSAv3(
        "RSA Leaf Certificate generated with an intermediate Certificate that is v3 (actually not a CA)."
            + "Root CA is v3",
        true, true),
    ROOTv3_CAv3_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA.", false,
        true),
    ROOTv3_CAv3_LEAF_RSAv3_Md2withRSA(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate uses MD2withRSA which is a weak algorithm.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_Md4withRSA(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate uses MD4withRSA which is a weak algorithm.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_Md5withRSA(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate uses MD5withRSA which is a weak algorithm.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_weakKey(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate uses a 512 bit RSA key with e=3 which is weak.",
        false, true),
    ECROOTv3_CAv3_LEAF_ECv3(
        "EC Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "All use ECC.",
        false, true),
    DSAROOTv3_CAv3_LEAF_DSAv3(
        "DSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "All use DSA.",
        false, true),
    DSAROOTv3_CAv3_LEAF_DHv3_KeyAgreement(
        "DH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses DSA while only the leaf uses DH with keyUsage keyAgreement only.",
        false, true),
    DSAROOTv3_CAv3_LEAF_DHv3(
        "DH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses DSA while only the leaf uses DH.",
        false, true),
    ECROOTv3_CAv3_LEAF_ECv3_KeyAgreement(
        "ECDH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses ECDSA while only the leaf uses ECDH with keyUsage keyAgreement only.",
        false, true),
    ECROOTv3_CAv3_LEAF_ECv3_KeyAgreement2(
        "ECDH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses ECDSA while only the leaf uses ECDH with keyUsage keyAgreement only. Uses a "
            + "different curve than the other testcase.",
        false, true),
    ROOTv3_CAv3_LEAF_DHv3_KeyAgreement(
        "DH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses RSA while only the leaf uses DH with keyUsage keyAgreement only.",
        false, true),
    ROOTv3_CAv3_LEAF_DHv3(
        "DH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses RSA while only the leaf uses DH.",
        false, true),
    ROOTv3_CAv3_LEAF_ECv3(
        "DH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses RSA while only the leaf uses ECDH/DSA.",
        false, true),
    ROOTv3_CAv3_LEAF_ECv3_KeyAgreement(
        "DH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses RSA while only the leaf uses ECDH with keyUsage keyAgreement only.",
        false, true),
    ROOTv3_CAv3_LEAF_ECv3_KeyAgreement2(
        "DH Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The chain uses RSA while only the leaf uses ECDH with keyUsage keyAgreement only.  Uses a "
            + "different curve than the other testcase.",
        false, true),
    DSAROOTv3_CAv3_LEAF_DSAv3_Sha1(
        "DSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "All use DSA and the leaf is signed using Sha1WithDSA (weak algo).",
        false, true),
    ECROOTv3_CAv3_LEAF_ECv3_Sha1(
        "EC Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "All use ECDSA and the leaf is signed using Sha1WithECDSA (weak algo).",
        false, true),
    ECROOTv3_CAv3_LEAF_ECv3_GarbageParameters(
        "EC Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. All use "
            + "ECC and the leaf certificate specifies garbage parameters in signatureAlgorithm and signature. Unless "
            + "the implementation ignores the parameters the test is expected to fail because a.) Parameters are not "
            + "null b.) parameters are invalid",
        false, true),
    DSAROOTv3_CAv3_LEAF_DSAv3_GarbageParameters(
        "DSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. All"
            + " use DSA and the leaf certificate specifies garbage parameters in signatureAlgorithm and signature"
            + ". Unless the implementation ignores the parameters the test is expected to fail because a.) Parameters"
            + " are not null b.) parameters are invalid",
        false, true),
    ECROOTv3_CAv3CustomCurve_LEAF_ECv3(
        "EC Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "All use ECC and the intermedia CA uses a custom curve (secp384r1 with custom generator).",
        false, true),
    ECROOTv3_Curveball_CAv3_LEAF_ECv3(
        "EC Leaf certificate generated based on the 'new' (root-)CA certificate with one intermediate CA."
            + "All use ECC and a ROOT certificate is included. The new ROOT certificate is generated based on "
            + "CVE-2020-0601 (Curveball/Chain of Fools).",
        false, true),
    ROOTv3_CAv3_LEAFv1_nLEAF_RSAv3(
        "RSA Leaf Certificate generated with an intermediate Certificate that is v1 (actually not a CA). "
            + "Root CA is v3.",
        false, true),
    ROOTv3_CAv3_LEAFv2_nLEAF_RSAv3(
        "RSA Leaf Certificate generated with an intermediate Certificate that is v2 (actually not a CA). "
            + "Root CA is v3.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAvNeg1_nLeaf_RSAv3(
        "RSA Leaf Certificate generated with an intermediate Certificate that is v -1 (actually not a CA). "
            + "Root CA is v3.",
        false, true),
    ROOTv1_CAv3_LEAFv1_nLEAF_RSAv3(
        "RSA Leaf Certificate generated with an intermediate Certificate that is v1 (actually not a CA). "
            + "Root CA is v1.",
        false, true),
    ROOTv1_CAv3_LEAFv2_nLEAF_RSAv3(
        "RSA Leaf Certificate generated with an intermediate Certificate that is v2 (actually not a CA). "
            + "Root CA is v1.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_expired(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The Leaf certificate is already expired.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_NotYetValid(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The Leaf certificate is only valid in the future.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_UnknownCritExt(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The Leaf certificate contains and unknown critical extension.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_UnknownExt(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The Leaf certificate contains and unknown extension.",
        false, true),
    ROOTv3_CAv3_ZeroPathLen_CAv3_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The first intermediate CA certificate specifies a PathLen of zero.",
        false, true),
    ROOTv3_CAv3_NoBasicConstraints_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate has no BasicConstraintsExtension.",
        false, true),
    ROOTv3_CAv3_CaFalse_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate has the CA flag set to false.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv2(
        "RSA Leaf certificate v2 generated based on the provided (root-)CA certificate with one intermediate CA.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv1(
        "RSA Leaf certificate v1 generated based on the provided (root-)CA certificate with one intermediate CA.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv1_UniqueIdentifiers(
        "RSA Leaf certificate v1 generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate has uniqueIDs for issuer and subject which MUST NOT appear in a v1 certificate.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAvNeg1(
        "RSA Leaf certificate v -1 generated based on the provided (root-)CA certificate with one intermediate CA.",
        false, true),
    ROOTv3_CAv3_KeyUsageNothing_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate specifies a KeyUsage of nothing.",
        false, true),
    ROOTv3_CAv3_KeyUsageDigitalSignatures_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate specifies a KeyUsage for digital signatures only.",
        false, true),
    ROOTv3_CAv3_NoKeyUsage_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate specifies no KeyUsage extension.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3__RDN_difference(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate and the leaf certificate use different ways to specify the same "
            + "subject/issuer. "
            + "A faulty implementation might use some abstruse string comparison to determine if issuer==subject which"
            + " could succeed in this case.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_extendedKeyUsageServerAuth(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The leaf certificates extended key usage extensions specifies server authentication only.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_extendedKeyUsageCodeSign(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The leaf certificates extended key usage extensions specifies code signing only.",
        false, true),
    ROOTv3_CAv3_NameConstraints_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate.",
        false, true),
    ROOTv3_CAv3_MalformedNameConstraints_LEAF_RSAv3(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate."
            + "Additionally the NameConstraints extension uses implicit tagging where explicit is expected, hence "
            + "presenting malformed ASN.1.",
        false, true),
    ROOTv3_CAv3_CAv3_PathLoop("Path loop created by two CA certificates signing each other.", false, true),
    ROOTv3_CAv3_LEAF_RSAv3_KeyUsageNothing(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificates key usage extensions allows no key usage at all.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_KeyUsageKeyAgreement(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificates key usage extensions allows key Agreement only.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_SelfSigned(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate points to the intermediate CA but is actually self signed.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_EmptySigned(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate points to the intermediate CA but isn't signed at all. (Empty signatureValue)",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_CertPolicy(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate and CA certificate has a certificate policy extension with the any value pointing"
            + " to an URL.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_NullSigned(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate points to the intermediate CA but isn't signed at all. (Null Signature)",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_MalformedAlgorithmParameters(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."
            + "The leaf certificate has malformed, but matching (tbsCert and Cert) parameters in the "
            + "SignatureAlgorithm.",
        false, true),
    ROOTv3_CAv3_NameConstraints_LEAF_RSAv3_SANCrit(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate "
            + "in the subject, but are met in the SAN. The extension is marked as critical.",
        false, true),
    ROOTv3_CAv3_NameConstraints_LEAF_RSAv3_SAN2Crit(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate "
            + "in the SAN, but are met in the Subject. The extension is marked as critical.",
        false, true),
    ROOTv3_CAv3_NameConstraints_LEAF_RSAv3_SAN(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate "
            + "in the subject, but are met in the SAN. The extension is marked as non critical.",
        false, true),
    ROOTv3_CAv3_NameConstraints_LEAF_RSAv3_SAN2(
        "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA. "
            + "The intermediate v3 CA certificate imposes NameConstraints that aren't met by the leaf certificate "
            + "in the SAN, but are met in the Subject. The extension is marked as non critical.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_CRLDistributionPoints(
        "RSA leaf certificate generated based on the provided (root-)CA certificate with on intermediate CA."
            + "The leaf certificate uses the CRL distribution point extension to specify the distribution point at "
            + "localhost. "
            + "If the implementation actually tries to verify the CRL and potentially fetch the CRL the test should "
            + "fail "
            + "since there is no valid CRL locally (no fetch) and none hosted at localhost (why would we even want "
            + "that).",
        false, true),
    ROOTv3_NewFakeChain_ROOTv3_CAv3_LEAF_RSAv3(
        "A certificate chain in which the ROOT certificate is a lookalike of the real root certificate "
            + "uses a different key. Intermediate CA and leaf certificate are as always.",
        false, true),
    ROOTv3_CAv3_LEAF_RSAv3_MismatchingAlgorithmParameters("RSA Leaf certificate generated based on the "
        + "provided (root-)CA certificate with one intermediate CA. In the leaf certificate the signatureAlgorithms "
        + "parameters differ in the tbsCertificate and outside.", false, true),
    ROOTv3_CAv3_LEAF_RSAv3_MismatchingAlgorithms1("RSA Leaf certificate generated based on the provided "
        + "(root-)CA certificate with one intermediate CA. In the leaf certificate the signature field "
        + "(type AlgorithmIdentifier) specifies a different algorithm than the signatureAlgorithm field in the "
        + "Certificate. Additionally the algorithm doesn't match the key.", false, true),
    ROOTv3_CAv3_LEAF_RSAv3_MismatchingAlgorithms2(
        "Same as ROOTv3_CAv3_LEAF_RSAv3_MismatchingAlgorithms1 " + "but the algorithm identifiers are swapped.", false,
        true);

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
