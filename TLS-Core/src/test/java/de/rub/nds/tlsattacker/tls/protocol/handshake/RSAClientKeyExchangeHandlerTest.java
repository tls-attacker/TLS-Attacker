/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RSAClientKeyExchangeHandlerTest {

    static byte[] rsaClientKeyExchange = ArrayConverter
            .hexStringToByteArray("100000820080"
                    + "7c215853b3265a49507cc4390195971539e6d0da12d7a5570dc74dcab5ddbad9d1003d0292938704d38d84488228eef26ed0f7edf54789f1da3ff2974cc4b100"
                    + "f4cb5c663bfb0bfcca6c2c41d3e241c70da8dde8dec9f755ae153e9aa2811cb50bf31e6960d55e5de2cb52020e5b634ed0f2e332912caf595b7e090821cee732");

    static byte[] clientRandom = ArrayConverter
            .hexStringToByteArray("3fddd7503dca1dd8c35d28a62c3667d77fba97f0d6c46c7e08fdb70f625edb53");

    static byte[] serverRandom = ArrayConverter
            .hexStringToByteArray("d05579f8ae2a5862864481764db12b8af57a910debb4a706f7a3b9c664e09dd8");

    RSAClientKeyExchangeHandler handler;

    TlsContext tlsContext;

    public RSAClientKeyExchangeHandlerTest() {
        // ECC does not work properly in the NSS provider
        Security.removeProvider("SunPKCS11-NSS");
        Security.addProvider(new BouncyCastleProvider());

        tlsContext = new TlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        tlsContext.setClientRandom(clientRandom);
        tlsContext.setServerRandom(serverRandom);

        try {
            ClassLoader loader = RSAClientKeyExchangeHandlerTest.class.getClassLoader();
            InputStream stream = loader.getResourceAsStream("rsa1024.jks");
            KeyStore ks = KeystoreHandler.loadKeyStore(stream, "password");
            tlsContext.getConfig().setKeyStore(ks);
            tlsContext.getConfig().setAlias("alias");
            tlsContext.getConfig().setPassword("password");
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException ex) {
            throw new ConfigurationException(
                    "Something went wrong loading key from Keystore or decrypting Premastersecret", ex);
        }
        try {
            String alias = tlsContext.getConfig().getAlias();
            java.security.cert.Certificate sunCert = tlsContext.getConfig().getKeyStore().getCertificate(alias);
            if (alias == null || sunCert == null) {
                throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
                        + "certificate alias and key? (Current alias: " + alias + ")");
            }
            byte[] certBytes = sunCert.getEncoded();

            ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
            org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);

            org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
            certs[0] = cert;
            Certificate tlsCerts = new Certificate(certs);
            tlsContext.setServerCertificate(tlsCerts);
            tlsContext.setServerCertificate(tlsCerts);
            tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        } catch (KeyStoreException | CertificateEncodingException | IOException ex) {
            throw new ConfigurationException("Certificate with the selected alias could not be found", ex);
        }
        handler = new RSAClientKeyExchangeHandler(tlsContext);
    }

    /**
     * Test of prepareMessageAction method, of class
     * RSAClientKeyExchangeHandler.
     */
    @Test
    public void testPrepareMessageAction() {
        handler.setProtocolMessage(new RSAClientKeyExchangeMessage(new TlsConfig()));

        RSAClientKeyExchangeMessage message = handler.getProtocolMessage();

        byte[] returned = handler.prepareMessageAction();

        handler.initializeProtocolMessage();

        int endPointer = handler.parseMessageAction(returned, 0);
        RSAClientKeyExchangeMessage messageparse = handler.getProtocolMessage();

        assertNotNull("Confirm function didn't return 'NULL'", returned);
        assertArrayEquals("Confirm returned message equals the expected message", message.getPremasterSecret()
                .getValue(), messageparse.getPremasterSecret().getValue());
    }

    /**
     * Test of parseMessageAction method, of class RSAClientKeyExchangeHandler.
     */
    @Test
    public void testParseMessageAction() {
        handler.initializeProtocolMessage();

        int endPointer = handler.parseMessageAction(rsaClientKeyExchange, 0);
        RSAClientKeyExchangeMessage message = handler.getProtocolMessage();

        byte[] exceptedPremastersecret = ArrayConverter
                .hexStringToByteArray("0303803ad3b1644b2c01c7d48be9bcf0b4cd2c7340c647594c7e3295c16cd958182143bee87a0907ff32486078fbe9ea");

        byte[] exceptedMastersecret = ArrayConverter
                .hexStringToByteArray("7F3E0FC44E1C9DB7A292FC89A5058B276C5C56B3E02B36CEADB3CC53BEADA78E4A8157E0A8AB65060D5EE99E05F5A313");

        assertNotNull("Confirm endPointer is not 'NULL'", endPointer);
        assertEquals("Confirm actual message length", 134, endPointer);
        assertEquals("Confirm message type", HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                message.getHandshakeMessageType());
        assertArrayEquals("Confirm excepted Premastersecret", exceptedPremastersecret, message.getPremasterSecret()
                .getValue());
        assertArrayEquals("Confirm excepted Mastersecret", exceptedMastersecret, message.getMasterSecret().getValue());
        assertTrue("Confirm encrypted Premastersecret Length",
                message.getEncryptedPremasterSecretLength().getValue() == 128);

    }

}
