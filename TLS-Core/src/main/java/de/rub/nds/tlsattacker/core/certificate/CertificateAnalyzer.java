/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.base.TbsCertificate;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import de.rub.nds.x509attacker.x509.base.publickey.DhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.DsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.EcdhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.Ed25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.Ed448PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.base.publickey.RsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X448PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.PublicParameters;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A class designed to answer questions about a given certificate */
public class CertificateAnalyzer {

    private static final Logger LOGGER = LogManager.getLogger();

    public static boolean isEllipticCurveCertificate(X509Certificate certificate) {

        X509PublicKey publicKey = getPublicKey(certificate);
        if (publicKey != null) {
            return publicKey.isEllipticCurve();
        } else {
            // Certificate does not seem to have a public key
            return false;
        }
    }

    public static CertificateKeyType getCertificateKeyType(X509Certificate certificate) {
        X509PublicKey publicKey = getPublicKey(certificate);
        if (publicKey == null) {
            return CertificateKeyType.NONE;
        }
        if (publicKey instanceof DhPublicKey) {
            return CertificateKeyType.DH;
        }
        if (publicKey instanceof RsaPublicKey) {
            return CertificateKeyType.RSA;
        }
        if (publicKey instanceof DsaPublicKey) {
            return CertificateKeyType.DSA;
        }
        if (publicKey instanceof EcdhEcdsaPublicKey) {
            return CertificateKeyType.ECDH_ECDSA;
        }
        if (publicKey instanceof EcdhPublicKey) {
            return CertificateKeyType.ECDH;
        }
        if (publicKey instanceof Ed25519PublicKey) {
            return CertificateKeyType.ED25519;
        }
        if (publicKey instanceof Ed448PublicKey) {
            return CertificateKeyType.ED448;
        }
        if (publicKey instanceof X25519PublicKey) {
            return CertificateKeyType.X25519;
        }
        if (publicKey instanceof X448PublicKey) {
            return CertificateKeyType.X448;
        }
        LOGGER.warn(
                "The public key "
                        + publicKey.toString()
                        + " has not been correctly integrated into TLS-Attacker. Returning NONE");
        return CertificateKeyType.NONE;
    }

    public static NamedGroup getEllipticCurveGroup(X509Certificate certificate) {
        if (isEllipticCurveCertificate(certificate)) {
            X509PublicKey publicKey = getPublicKey(certificate);
            if (publicKey instanceof X25519PublicKey) {
                return NamedGroup.ECDH_X25519;
            } else if (publicKey instanceof X448PublicKey) {
                return NamedGroup.ECDH_X448;
            } else {
                throw new UnsupportedOperationException("not implemented yet");
            }
        } else {
            return null;
        }
    }

    public static X509PublicKey getPublicKey(X509Certificate certificate) {
        Optional<TbsCertificate> optionalTbs = Optional.ofNullable(certificate.getTbsCertificate());
        Optional<SubjectPublicKeyInfo> optionalPublicKeyType =
                optionalTbs.map(TbsCertificate::getSubjectPublicKeyInfo);
        Optional<PublicKeyBitString> publicKeyString =
                optionalPublicKeyType.map(SubjectPublicKeyInfo::getSubjectPublicKeyBitString);
        var publicKeyOptional = publicKeyString.map(PublicKeyBitString::getPublicKey);
        return (X509PublicKey) publicKeyOptional.get();
    }

    public static PublicParameters getPublicParameters(X509Certificate certificate) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    public static NamedGroup getPublicNamedGroup(X509Certificate certificate) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    public static NamedGroup getSignatureNamedGroup(X509Certificate certificate) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
}
