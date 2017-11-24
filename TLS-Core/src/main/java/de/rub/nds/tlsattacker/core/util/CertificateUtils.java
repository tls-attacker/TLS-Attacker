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
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CertificateUtils {

    protected static final Logger LOGGER = LogManager.getLogger(CertificateUtils.class.getName());

    /**
     * Parses the leaf Certificate PublicKey from the CertificateStructure
     *
     * @param cert
     * @return
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
            throw new IOException();
        }
    }

    public static ECPublicKeyParameters extractECPublicKeyParameters(Certificate cert) throws IOException {
        if (hasECParameters(cert)) {
            SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
            return (ECPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
        } else {
            throw new IOException();
        }
    }

    public static BigInteger extractRSAModulus(Certificate cert) throws IOException {
        if (hasRSAParameters(cert)) {
            RSAPublicKey rsaPubKey = (RSAPublicKey) parsePublicKey(cert);
            return rsaPubKey.getModulus();
        } else {
            throw new IOException();
        }
    }

    public static BigInteger extractRSAPublicKey(Certificate cert) throws IOException {
        if (hasRSAParameters(cert)) {
            RSAPublicKey rsaPubKey = (RSAPublicKey) parsePublicKey(cert);
            return rsaPubKey.getPublicExponent();
        } else {
            throw new IOException();
        }
    }
}
