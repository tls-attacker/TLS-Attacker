/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyInfo;
import de.rub.nds.x509attacker.x509.base.TbsCertificate;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyContent;
import de.rub.nds.x509attacker.x509.base.publickey.X509DhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509DsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509EcdhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509Ed25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509Ed448PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509X25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509X448PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DssParameters;
import java.math.BigInteger;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A class designed to answer questions about a given certificate */
public class CertificateAnalyzer {

    private static final Logger LOGGER = LogManager.getLogger();

    public static boolean isEllipticCurveCertificate(X509Certificate certificate) {

        PublicKeyContent publicKey = getPublicKey(certificate);
        if (publicKey != null) {
            return publicKey.isEllipticCurve();
        } else {
            // Certificate does not seem to have a public key
            return false;
        }
    }

    public static X509PublicKeyType getCertificateKeyType(X509Certificate certificate) {
        PublicKeyContent publicKey = getPublicKey(certificate);
        if (publicKey == null) {
            return null;
        }
        if (publicKey instanceof X509DhPublicKey) {
            return X509PublicKeyType.DH;
        }
        if (publicKey instanceof X509RsaPublicKey) {
            return X509PublicKeyType.RSA;
        }
        if (publicKey instanceof X509DsaPublicKey) {
            return X509PublicKeyType.DSA;
        }
        if (publicKey instanceof X509EcdhEcdsaPublicKey) {
            return X509PublicKeyType.ECDH_ECDSA;
        }
        if (publicKey instanceof X509EcdhPublicKey) {
            return X509PublicKeyType.ECDH_ONLY;
        }
        if (publicKey instanceof X509Ed25519PublicKey) {
            return X509PublicKeyType.ED25519;
        }
        if (publicKey instanceof X509Ed448PublicKey) {
            return X509PublicKeyType.ED448;
        }
        if (publicKey instanceof X509X25519PublicKey) {
            return X509PublicKeyType.X25519;
        }
        if (publicKey instanceof X509X448PublicKey) {
            return X509PublicKeyType.X448;
        }
        LOGGER.warn(
                "The public key "
                        + publicKey.toString()
                        + " has not been correctly integrated into TLS-Attacker. Returning NONE");
        return null;
    }

    public static NamedGroup getEllipticCurveGroup(X509Certificate certificate) {
        if (isEllipticCurveCertificate(certificate)) {
            PublicKeyContent publicKey = getPublicKey(certificate);
            if (publicKey instanceof X509X25519PublicKey) {
                return NamedGroup.ECDH_X25519;
            } else if (publicKey instanceof X509X448PublicKey) {
                return NamedGroup.ECDH_X448;
            } else {
                throw new UnsupportedOperationException("not implemented yet");
            }
        } else {
            return null;
        }
    }

    public static PublicKeyContent getPublicKey(X509Certificate certificate) {
        Optional<TbsCertificate> optionalTbs = Optional.ofNullable(certificate.getTbsCertificate());
        Optional<SubjectPublicKeyInfo> optionalPublicKeyType =
                optionalTbs.map(TbsCertificate::getSubjectPublicKeyInfo);
        Optional<PublicKeyBitString> publicKeyString =
                optionalPublicKeyType.map(SubjectPublicKeyInfo::getSubjectPublicKeyBitString);
        Optional<PublicKeyContent> publicKeyContentOptional =
                publicKeyString.map(PublicKeyBitString::getX509PublicKeyContent);
        return (PublicKeyContent) publicKeyContentOptional.get();
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

    public static PublicKeyContainer getPublicKeyContainer(X509Certificate certificate) {
        X509PublicKeyType certificateKeyType = getCertificateKeyType(certificate);
        switch (certificateKeyType) {
            case DH:
                BigInteger publicKey =
                        ((X509DhPublicKey) getPublicKey(certificate))
                                .getPublicKey()
                                .getValue()
                                .getValue();
                BigInteger generator =
                        ((X509DhParameters) getPublicParameters(certificate))
                                .getG()
                                .getValue()
                                .getValue();
                BigInteger modulus =
                        ((X509DhParameters) getPublicParameters(certificate))
                                .getP()
                                .getValue()
                                .getValue();
                return new DhPublicKey(publicKey, generator, modulus);
            case DSA:
                BigInteger Q =
                        ((X509DssParameters) getPublicParameters(certificate))
                                .getQ()
                                .getValue()
                                .getValue();
                BigInteger X =
                        ((X509DsaPublicKey) getPublicKey(certificate))
                                .getPublicKeyY()
                                .getValue()
                                .getValue();
                generator =
                        ((X509DssParameters) getPublicParameters(certificate))
                                .getG()
                                .getValue()
                                .getValue();
                modulus =
                        ((X509DssParameters) getPublicParameters(certificate))
                                .getP()
                                .getValue()
                                .getValue();
                return new DsaPublicKey(Q, X, generator, modulus);
            case ECDH_ECDSA:
                BigInteger xCoordinate =
                        ((X509EcdhEcdsaPublicKey) getPublicKey(certificate))
                                .getxCoordinate()
                                .getValue();
                BigInteger yCoordinate =
                        ((X509EcdhEcdsaPublicKey) getPublicKey(certificate))
                                .getyCoordinate()
                                .getValue();
                NamedEllipticCurveParameters parameters =
                        (NamedEllipticCurveParameters)
                                getEllipticCurveGroup(certificate).getGroupParameters();
                return new EcdsaPublicKey(
                        parameters.getCurve().getPoint(xCoordinate, yCoordinate), parameters);
            case ECDH_ONLY:
                xCoordinate =
                        ((X509EcdhPublicKey) getPublicKey(certificate)).getxCoordinate().getValue();
                yCoordinate =
                        ((X509EcdhPublicKey) getPublicKey(certificate)).getyCoordinate().getValue();
                parameters =
                        (NamedEllipticCurveParameters)
                                getEllipticCurveGroup(certificate).getGroupParameters();
                return new EcdhPublicKey(
                        parameters.getCurve().getPoint(xCoordinate, yCoordinate), parameters);
            case RSA:
                modulus =
                        ((X509RsaPublicKey) getPublicKey(certificate))
                                .getRsaPublicKeyContentSequence()
                                .getModulus()
                                .getValue()
                                .getValue();
                BigInteger publicExponent =
                        ((X509RsaPublicKey) getPublicKey(certificate))
                                .getRsaPublicKeyContentSequence()
                                .getPublicExponent()
                                .getValue()
                                .getValue();
                return new RsaPublicKey(publicExponent, modulus);
            default:
                throw new UnsupportedOperationException(
                        "PublicKeyContainer " + certificateKeyType + " not yet implemented");
        }
    }
}
