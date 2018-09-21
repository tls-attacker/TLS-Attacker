/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.modifiablevariable.util.BadRandom;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Implemented based on
 * http://codereview.stackexchange.com/questions/117944/bouncycastle
 * -implementation-with-x509certificate-signing-keystore-generation-a
 */
public class KeyStoreGenerator {

    public static final String PASSWORD = "password";
    public static final String ALIAS = "alias";

    public static KeyPair createRSAKeyPair(int bits, BadRandom random) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(bits, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static KeyPair createECKeyPair(int bits, BadRandom random) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(bits, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static KeyPair createGost01KeyPair(String curve, BadRandom random) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410");
        keyPairGenerator.initialize(spec, random);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair createGost12KeyPair(String curve, BadRandom random) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410-2012");
        keyPairGenerator.initialize(spec, random);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyStore createKeyStore(KeyPair keyPair, BadRandom random) throws CertificateException, IOException,
            InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, OperatorCreationException {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        X500Name issuerName = new X500Name("CN=127.0.0.1, O=TLS-Attacker, L=RUB, ST=NRW, C=DE");
        X500Name subjectName = issuerName;

        BigInteger serial = BigInteger.valueOf(random.nextInt());
        Date before = new Date(System.currentTimeMillis() - 5000);
        Date after = new Date(System.currentTimeMillis() + 600000);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, before, after,
                subjectName, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment);
        builder.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

        String algorithm = createSigningAlgorithm(keyPair);
        X509Certificate cert = signCertificate(algorithm, builder, privateKey);
        cert.checkValidity(new Date());
        cert.verify(publicKey);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry(ALIAS, privateKey, PASSWORD.toCharArray(), new java.security.cert.Certificate[] { cert });

        return keyStore;
    }

    private static X509Certificate signCertificate(String algorithm, X509v3CertificateBuilder builder,
            PrivateKey privateKey) throws OperatorCreationException, CertificateException {
        ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(privateKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static String createSigningAlgorithm(KeyPair keyPair) {
        switch (keyPair.getPublic().getAlgorithm()) {
            case "RSA":
                return "SHA256withRSA";
            case "EC":
                return "SHA256withECDSA";
            case "DH":
                return "SHA256withDSA";
            case "ECGOST3410":
                return "GOST3411WITHECGOST3410";
            case "ECGOST3410-2012":
                BigInteger x = ((BCECGOST3410_2012PublicKey) keyPair.getPublic()).getQ().getAffineXCoord()
                        .toBigInteger();
                if (x.bitLength() > 256) {
                    return "GOST3411-2012-512WITHGOST3410-2012-512";
                } else {
                    return "GOST3411-2012-256WITHGOST3410-2012-256";
                }
            default:
                throw new UnsupportedOperationException("Algorithm " + keyPair.getPublic().getAlgorithm()
                        + " not supported");
        }
    }

    private KeyStoreGenerator() {
    }

}
