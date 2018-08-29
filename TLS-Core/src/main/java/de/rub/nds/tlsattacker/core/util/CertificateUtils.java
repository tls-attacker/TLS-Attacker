/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class CertificateUtils {

    protected static final Logger LOGGER = LogManager.getLogger(CertificateUtils.class.getName());

    /**
     * Parses the leaf Certificate PublicKey from the CertificateStructure
     *
     * @param cert
     *            The Certificate from which the PublicKey should be extracted
     * @return The parsed PublicKey
     */
    public static PublicKey parsePublicKey(Certificate cert) {
        try {
            X509CertificateObject certObj = new X509CertificateObject(cert.getCertificateAt(0));
            return certObj.getPublicKey();
        } catch (CertificateParsingException | IllegalArgumentException | ClassCastException ex) {
            LOGGER.warn("Could not extract public key from Certificate!");
            LOGGER.debug(ex);
            return null;
        }
    }

    public static ECPrivateKey ecPrivateKeyFromPrivateKey(PrivateKey key) {
        ECPrivateKey k;
        try {
            KeyFactory f = KeyFactory.getInstance("EC");
            ECPrivateKeySpec s = f.getKeySpec(key, ECPrivateKeySpec.class);
            k = (ECPrivateKey) f.generatePrivate(s);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException | ClassCastException ex) {
            LOGGER.warn("Could not convert key to EC private key!");
            LOGGER.debug(ex);
            return null;
        }
        return k;
    }

    public static RSAPrivateKey rsaPrivateKeyFromPrivateKey(PrivateKey key) {
        RSAPrivateKey k;
        try {
            KeyFactory f = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec s = f.getKeySpec(key, RSAPrivateKeySpec.class);
            k = (RSAPrivateKey) f.generatePrivate(s);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException | ClassCastException ex) {
            LOGGER.warn("Could not convert key to EC private key!");
            LOGGER.debug(ex);
            return null;
        }
        return k;
    }

    public static boolean hasDHParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        return keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.dhpublicnumber);
    }

    public static boolean hasECParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        return keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey);
    }

    public static boolean hasRSAParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        PublicKey key = parsePublicKey(cert);
        return key != null && key instanceof RSAPublicKey;
    }

    public static DHPublicKeyParameters extractDHPublicKeyParameters(Certificate cert) throws IOException {
        if (hasDHParameters(cert)) {
            SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
            return (DHPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
        } else {
            return null;
        }
    }

    public static ECPublicKeyParameters extractECPublicKeyParameters(Certificate cert) throws IOException {
        if (hasECParameters(cert)) {
            SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
            return (ECPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
        } else {
            return null;
        }
    }

    public static BigInteger extractRSAModulus(Certificate cert) throws IOException {
        if (hasRSAParameters(cert)) {
            RSAPublicKey rsaPubKey = (RSAPublicKey) parsePublicKey(cert);
            return rsaPubKey.getModulus();
        } else {
            return null;
        }
    }

    public static BigInteger extractRSAModulus(PrivateKey key) throws IOException {
        if (key instanceof RSAPrivateKey) {
            return ((RSAPublicKey) key).getModulus();
        } else {
            return null;
        }
    }

    public static BigInteger extractRSAPrivateExponent(PrivateKey key) throws IOException {
        if (key instanceof RSAPrivateKey) {
            return ((RSAPrivateKey) ((RSAPublicKey) key)).getPrivateExponent();
        } else {
            return null;
        }
    }

    public static BigInteger extractRSAPublicKey(Certificate cert) throws IOException {
        if (hasRSAParameters(cert)) {
            RSAPublicKey rsaPubKey = (RSAPublicKey) parsePublicKey(cert);
            return rsaPubKey.getPublicExponent();
        } else {
            return null;
        }
    }

    public static BCECGOST3410PublicKey extract01PublicKey(Certificate cert) throws IOException {
        SubjectPublicKeyInfo publicKey = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        return (BCECGOST3410PublicKey) new JcaPEMKeyConverter().getPublicKey(publicKey);
    }

    public static BCECGOST3410_2012PublicKey extract12PublicKey(Certificate cert) throws IOException {
        SubjectPublicKeyInfo publicKey = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        return (BCECGOST3410_2012PublicKey) new JcaPEMKeyConverter().getPublicKey(publicKey);
    }

    public static boolean hasGOSTParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        return keyInfo.getAlgorithm().getAlgorithm().equals(CryptoProObjectIdentifiers.gostR3410_94);
    }

    public static boolean hasGost01EcParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        ASN1ObjectIdentifier alg = keyInfo.getAlgorithm().getAlgorithm();
        return alg.equals(CryptoProObjectIdentifiers.gostR3410_2001);
    }

    public static boolean hasGost12EcParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        ASN1ObjectIdentifier alg = keyInfo.getAlgorithm().getAlgorithm();
        return alg.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)
                || alg.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512);
    }

}
