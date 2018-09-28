/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMParser;
import org.junit.Assert;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

public class TestCertificates {

    public static final String keyStoreAlias = "keyStoreFromRsaPem";
    public static final String keyStorePass = "keyStoreFromRsaPem";

    private static final byte[] cert1 = ArrayConverter
            .hexStringToByteArray("0003970003943082039030820278A003020102020900A650C00794049FCD300D06092A864886F70D01010B0500305C310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B65723020170D3137303731333132353331385A180F32313137303631393132353331385A305C310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B657230820122300D06092A864886F70D01010105000382010F003082010A0282010100C8820D6C3CE84C8430F6835ABFC7D7A912E1664F44578751F376501A8C68476C3072D919C5D39BD0DBE080E71DB83BD4AB2F2F9BDE3DFFB0080F510A5F6929C196551F2B3C369BE051054C877573195558FD282035934DC86EDAB8D4B1B7F555E5B2FEE7275384A756EF86CB86793B5D1333F0973203CB96966766E655CD2CCCAE1940E4494B8E9FB5279593B75AFD0B378243E51A88F6EB88DEF522A8CD5C6C082286A04269A2879760FCBA45005D7F2672DD228809D47274F0FE0EA5531C2BD95366C05BF69EDC0F3C3189866EDCA0C57ADCCA93250AE78D9EACA0393A95FF9952FC47FB7679DD3803E6A7A6FA771861E3D99E4B551A4084668B111B7EEF7D0203010001A3533051301D0603551D0E04160414E7A92FE5543AEE2FF7592F800AC6E66541E3268B301F0603551D23041830168014E7A92FE5543AEE2FF7592F800AC6E66541E3268B300F0603551D130101FF040530030101FF300D06092A864886F70D01010B050003820101000D5C11E28CF19D1BC17E4FF543695168570AA7DB85B3ECB85405392A0EDAFE4F097EE4685B7285E3D9B869D23257161CA65E20B5E6A585D33DA5CD653AF81243318132C9F64A476EC08BA80486B3E439F765635A7EA8A969B3ABD8650036D74C5FC4A04589E9AC8DC3BE2708743A6CFE3B451E3740F735F156D6DC7FFC8A2C852CD4E397B942461C2FCA884C7AFB7EBEF7918D6AAEF1F0D257E959754C4665779FA0E3253EF2BEDBBD5BE5DA600A0A68E51D2D1C125C4E198669A6BC715E8F3884E9C3EFF39D40838ADA4B1F38313F6286AA395DC6DEA9DAF49396CF12EC47EFA7A0D3882F8B84D9AEEFFB252C6B81A566609605FBFD3F0D17E5B12401492A1A");

    public static Certificate getTestCertificate() {
        try {
            ByteArrayInputStream bin = new ByteArrayInputStream(cert1);
            ASN1InputStream ain = new ASN1InputStream(bin);
            Certificate obj = Certificate.parse(ain);
            return obj;
        } catch (IOException ex) {
        }
        return null;
    }

    public static X509CertificateObject getTestCertificateObject() {
        try {
            X509CertificateObject obj = new X509CertificateObject(getTestCertificate().getCertificateAt(0));
            return obj;
        } catch (CertificateParsingException ex) {
        }
        return null;
    }

    public static KeyPair keyPairFromStore(KeyStore keyStore, String keyAlias, String keyPass)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        PrivateKey privKey = (PrivateKey) keyStore.getKey(keyAlias, keyPass.toCharArray());
        java.security.cert.Certificate cert = keyStore.getCertificate(keyAlias);
        PublicKey pubKey = cert.getPublicKey();
        return new KeyPair(pubKey, privKey);
    }

    public static KeyPair keyPairFromStore(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException,
            UnrecoverableKeyException {
        return keyPairFromStore(keyStore, keyStoreAlias, keyStorePass);
    }

    /**
     * Initialize a KeyStore from an ordinary OpenSSL RSA (cert,key) pair as
     * generated with
     * "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem" For a
     * less hacky version check
     * http://ludup.com/content/loading-pem-keys-and-certificates-from-java/
     * 
     * @param rawPemCert
     *            PEM certificate, i.e. the output of `cat cert.pem` as a simple
     *            String
     * @param rawPemKey
     *            Certificate key, i.e the output of `cat key.pem` as a simple
     *            String
     * @param keyAlias
     *            Alias of the key in the returned KeyStore
     * @param keyPass
     *            Password of the key in the returned KeyStore
     * @return
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.security.cert.CertificateException
     * @throws java.security.KeyStoreException
     */
    public static KeyStore keyStoreFromRsaPem(byte[] rawPemCert, byte[] rawPemKey, String keyAlias, String keyPass)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException,
            KeyStoreException {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(rawPemCert)));
        X509CertificateHolder certHolder = (X509CertificateHolder) pemParser.readObject();
        java.security.cert.Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                certHolder);

        byte[] encPubKey = certHolder.getSubjectPublicKeyInfo().getEncoded();
        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encPubKey));
        assertNotNull(pubKey);
        pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(rawPemKey)));
        PrivateKeyInfo privKeyInfo = (PrivateKeyInfo) pemParser.readObject();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyInfo.getEncoded());
        PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry(keyAlias, privKey, keyPass.toCharArray(), new java.security.cert.Certificate[] { cert });

        return keyStore;
    }

    public static KeyStore keyStoreFromRsaPem(byte[] rawPemCert, byte[] rawPemKey) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, KeyStoreException {

        return keyStoreFromRsaPem(rawPemCert, rawPemKey, keyStoreAlias, keyStorePass);
    }

    public TestCertificates() {
    }

    @Test
    public void testTestCertificates() {
        Assert.assertNotNull(getTestCertificate());
        Assert.assertNotNull(getTestCertificateObject());

    }
}
