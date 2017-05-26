/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Base64;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TestCertificates {

    public static final String keyStoreAlias = "keyStoreFromRsaPem";
    public static final String keyStorePass = "keyStoreFromRsaPem";

    private static final byte[] cert1 = Base64
            .decode("MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
                    + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
                    + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
                    + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
                    + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2"
                    + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
                    + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
                    + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l"
                    + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv"
                    + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re"
                    + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO"
                    + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE"
                    + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy"
                    + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0"
                    + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw"
                    + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL"
                    + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4"
                    + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF" + "5/8=");

    public static Certificate getTestCertificate() {
        try {
            ByteArrayInputStream bin = new ByteArrayInputStream(cert1);
            ASN1InputStream ain = new ASN1InputStream(bin);
            Certificate obj = Certificate.parse(ain);
            return obj;
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static X509CertificateObject getTestCertificateObject() {
        try {
            X509CertificateObject obj = new X509CertificateObject(getTestCertificate().getCertificateAt(0));
            return obj;
        } catch (CertificateParsingException ex) {
            ex.printStackTrace();
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
     * "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem"
     * 
     * For a less hacky version check
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
}
