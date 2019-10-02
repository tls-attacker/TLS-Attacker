/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDHPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDSAPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRSAPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRsaPublicKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSequence;
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
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class CertificateUtils {

    private static final Logger LOGGER = LogManager.getLogger();

    public static CustomPrivateKey parseCustomPrivateKey(PrivateKey key) {
        if (key instanceof RSAPrivateKey) {
            RSAPrivateKey privKey = (RSAPrivateKey) key;
            return new CustomRSAPrivateKey(privKey.getModulus(), privKey.getPrivateExponent());
        } else if (key instanceof DSAPrivateKey) {
            DSAPrivateKey privKey = (DSAPrivateKey) key;
            return new CustomDSAPrivateKey(privKey.getX(), privKey.getParams().getP(), privKey.getParams().getQ(),
                    privKey.getParams().getG());
        } else if (key instanceof DHPrivateKey) {
            DHPrivateKey privKey = (DHPrivateKey) key;
            return new CustomDHPrivateKey(privKey.getX(), privKey.getParams().getP(), privKey.getParams().getG());
        } else if (key instanceof ECPrivateKey) {
            ECPrivateKey privKey = (ECPrivateKey) key;

            return new CustomECPrivateKey(privKey.getS(), NamedGroup.getNamedGroup(privKey));
        } else {
            throw new UnsupportedOperationException("This private key is not supporter:" + key.toString());
        }
    }

    public static CustomPublicKey parseCustomPublicKey(PublicKey key) {
        if (key instanceof RSAPublicKey) {
            LOGGER.trace("Found an RSA PublicKey");
            RSAPublicKey pubKey = (RSAPublicKey) key;
            return new CustomRsaPublicKey(pubKey.getPublicExponent(), pubKey.getModulus());
        } else if (key instanceof DSAPublicKey) {
            LOGGER.trace("Found a DSA PublicKey");
            DSAPublicKey pubKey = (DSAPublicKey) key;
            return new CustomDsaPublicKey(pubKey.getParams().getP(), pubKey.getParams().getQ(), pubKey.getParams()
                    .getG(), pubKey.getY());
        } else if (key instanceof DHPublicKey) {
            LOGGER.trace("Found a DH PublicKey");
            DHPublicKey pubKey = (DHPublicKey) key;
            return new CustomDhPublicKey(pubKey.getParams().getP(), pubKey.getParams().getG(), pubKey.getY());
        } else if (key instanceof ECPublicKey) {
            LOGGER.trace("Found an EC PublicKey");
            ECPublicKey pubKey = (ECPublicKey) key;
            NamedGroup group = NamedGroup.getNamedGroup(pubKey);
            if (group == null) {
                return new CustomEcPublicKey(pubKey.getW().getAffineX(), pubKey.getW().getAffineY(),
                        GOSTCurve.fromNamedSpec((ECNamedCurveSpec) pubKey.getParams()));
            } else {
                return new CustomEcPublicKey(pubKey.getW().getAffineX(), pubKey.getW().getAffineY(), group);
            }
        } else {
            throw new UnsupportedOperationException("This public key is not supported:" + key);
        }
    }

    /**
     * Parses the leaf Certificate PublicKey from the CertificateStructure
     *
     * @param cert
     *            The Certificate from which the PublicKey should be extracted
     * @return The parsed PublicKey
     */
    public static PublicKey parsePublicKey(Certificate cert) {
        try {
            X509Certificate x509Cert = X509Certificate.getInstance(cert.getCertificateAt(0).getEncoded());
            PublicKey key = x509Cert.getPublicKey();
            if (key instanceof RSAPublicKey || key instanceof ECPublicKey || key instanceof DSAPublicKey) {
                return key;
            } else {
                // Since java does not support DH nativly we can try to manually
                // parse this, this may fail
                ASN1InputStream stream = new ASN1InputStream(cert.getCertificateAt(0).getSubjectPublicKeyInfo()
                        .toASN1Primitive().getEncoded());
                DLSequence sequence = (DLSequence) stream.readObject();
                DLSequence objectAt = (DLSequence) sequence.getObjectAt(0).toASN1Primitive();
                DLSequence dhparams = (DLSequence) objectAt.getObjectAt(1);
                ASN1Integer asnModulus = (ASN1Integer) dhparams.getObjectAt(0); // modulus
                ASN1Integer asnGenerator = (ASN1Integer) dhparams.getObjectAt(1); // generator
                BigInteger publicKey = new BigInteger(1, x509Cert.getPublicKey().getEncoded());
                return new CustomDhPublicKey(asnModulus.getPositiveValue(), asnGenerator.getPositiveValue(), publicKey);
            }
        } catch (IOException | CertificateException | IllegalArgumentException | ClassCastException ex) {
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
        if (keyInfo == null) {
            return false;
        }
        return keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey);
    }

    public static boolean hasRSAParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        PublicKey key = parsePublicKey(cert);
        return key != null && key instanceof RSAPublicKey;
    }

    public static boolean hasDsaParameters(Certificate cert) {
        if (cert.isEmpty()) {
            return false;
        }
        PublicKey key = parsePublicKey(cert);
        return key != null && key instanceof DSAPublicKey;
    }

    public static BigInteger extractDsaPublicKey(Certificate cert) {
        if (hasDsaParameters(cert)) {
            DSAPublicKey parsePublicKey = (DSAPublicKey) parsePublicKey(cert);
            return parsePublicKey.getY();
        } else {
            return null;
        }
    }

    public static BigInteger extractDsaGenerator(Certificate cert) {
        if (hasDsaParameters(cert)) {
            DSAPublicKey parsePublicKey = (DSAPublicKey) parsePublicKey(cert);
            return parsePublicKey.getParams().getG();
        } else {
            return null;
        }
    }

    public static BigInteger extractDsaPrimeQ(Certificate cert) {
        if (hasDsaParameters(cert)) {
            DSAPublicKey parsePublicKey = (DSAPublicKey) parsePublicKey(cert);
            return parsePublicKey.getParams().getQ();
        } else {
            return null;
        }
    }

    public static BigInteger extractDsaPrimeP(Certificate cert) {
        if (hasDsaParameters(cert)) {
            DSAPublicKey parsePublicKey = (DSAPublicKey) parsePublicKey(cert);
            return parsePublicKey.getParams().getP();
        } else {
            return null;
        }
    }

    public static DHPublicKeyParameters extractDHPublicKeyParameters(Certificate cert) throws IOException {
        if (hasDHParameters(cert)) {
            if (cert.isEmpty()) {
                return null;
            }
            SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
            return (DHPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
        } else {
            return null;
        }
    }

    public static ECPublicKeyParameters extractECPublicKeyParameters(Certificate cert) throws IOException {
        if (hasECParameters(cert)) {
            if (cert.isEmpty()) {
                return null;
            }
            SubjectPublicKeyInfo keyInfo = cert.getCertificateAt(0).getSubjectPublicKeyInfo();
            if (keyInfo == null) {
                return null;
            }
            return (ECPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
        } else {
            return null;
        }
    }

    public static BigInteger extractRSAModulus(Certificate cert) throws IOException {
        if (hasRSAParameters(cert)) {
            if (cert.isEmpty()) {
                return null;
            }
            RSAPublicKey rsaPubKey = (RSAPublicKey) parsePublicKey(cert);
            return rsaPubKey.getModulus();
        } else {
            return null;
        }
    }

    public static BigInteger extractRSAModulus(PrivateKey key) throws IOException {
        if (key instanceof RSAPrivateKey) {
            return ((RSAKey) key).getModulus();
        } else {
            return null;
        }
    }

    public static BigInteger extractRSAPrivateExponent(PrivateKey key) throws IOException {
        if (key instanceof RSAPrivateKey) {
            return ((RSAPrivateKey) ((RSAPrivateKey) key)).getPrivateExponent();
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

    private CertificateUtils() {
    }
}
