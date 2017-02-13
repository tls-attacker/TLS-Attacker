/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.protocol.handshake.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * Tests for ECDHE key exchange handler, with values from wireshark
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHEServerKeyExchangeHandlerTest {

    static byte[] testServerKeyExchangeDSA = ArrayConverter
            .hexStringToByteArray("0c0000b90040da583c16d9852289d0e4af756f4cca92dd4be533b804fb0fed94ef9c8a4403ed574650d3"
                    + "6999db29d776276ba2d3d412e218f4dd1e084cf6d8003e7c4774e833000102004006a14fecf0b2e7fae2b30d87961620"
                    + "7fb1022ce1000d87c3e98ede5a053799d61adc622daac01b0966232425784ffd3493f2ab3bfa109361a42c28c7ba4af7"
                    + "6c0402002e302c02144f232c10ad1fcfb92b3bedc7c0deddd5c04908ad02142211f07d891eb18a1e0d58dfba4949ffe5"
                    + "961451");

    static byte[] clientRandom = ArrayConverter
            .hexStringToByteArray("3fddd7503dca1dd8c35d28a62c3667d77fba97f0d6c46c7e08fdb70f625edb53");

    static byte[] serverRandom = ArrayConverter
            .hexStringToByteArray("d05579f8ae2a5862864481764db12b8af57a910debb4a706f7a3b9c664e09dd8");

    DHEServerKeyExchangeHandler handler;

    TlsContext tlsContext;

    public DHEServerKeyExchangeHandlerTest() {
    }

    @Before
    public void init() {

        // ECC does not work properly in the NSS provider
        Security.removeProvider("SunPKCS11-NSS");
        Security.addProvider(new BouncyCastleProvider());

        tlsContext = new TlsContext(new TlsConfig());
        tlsContext.setClientRandom(clientRandom);
        tlsContext.setServerRandom(serverRandom);
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        try {
            ClassLoader loader = DHEServerKeyExchangeHandlerTest.class.getClassLoader();
            InputStream stream = loader.getResourceAsStream("rsa1024.jks");
            KeyStore ks = KeystoreHandler.loadKeyStore(stream, "password");
            tlsContext.getConfig().setKeyStore(ks);
            tlsContext.getConfig().setAlias("alias");
            tlsContext.getConfig().setPassword("password");
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException ex) {
            throw new ConfigurationException("Something went wrong loading key from Keystore", ex);
        }
        handler = new DHEServerKeyExchangeHandler(tlsContext);

    }

    /**
     * Test of parseMessageAction method, of class DHEServerKeyExchangeHandler.
     */
    @Test
    public void testParseMessageDSA() {
        handler.initializeProtocolMessage();

        int endPointer = handler.parseMessageAction(testServerKeyExchangeDSA, 0);
        DHEServerKeyExchangeMessage message = (DHEServerKeyExchangeMessage) handler.getProtocolMessage();

        assertEquals("Message type must be ServerKeyExchange", HandshakeMessageType.SERVER_KEY_EXCHANGE,
                message.getHandshakeMessageType());
        assertEquals("Message length must be 185", new Integer(185), message.getLength().getValue());
        assertEquals("p length must be 64", new Integer(64), message.getpLength().getValue());
        assertEquals("g length must be ", new Integer(1), message.getgLength().getValue());
        assertEquals("g must be 2", new BigInteger("2"), message.getG().getValue());

        assertEquals("Public key length is 64", new Integer(64), message.getPublicKeyLength().getValue());
        assertEquals("Hash must be SHA256", HashAlgorithm.SHA256,
                HashAlgorithm.getHashAlgorithm(message.getHashAlgorithm().getValue()));
        assertEquals("Signature must be DSA", SignatureAlgorithm.DSA,
                SignatureAlgorithm.getSignatureAlgorithm(message.getSignatureAlgorithm().getValue()));
        assertEquals("Signature length must be 46", new Integer(46), message.getSignatureLength().getValue());

        assertEquals("The pointer has to return the length of the protocol message", testServerKeyExchangeDSA.length,
                endPointer);
    }

    @Test
    public void testIsCorrectProtocolMessage() {
        DHEServerKeyExchangeMessage sem = new DHEServerKeyExchangeMessage(new TlsConfig());
        assertTrue(handler.isCorrectProtocolMessage(sem));

        CertificateMessage cm = new CertificateMessage(new TlsConfig());
        assertFalse(handler.isCorrectProtocolMessage(cm));
    }

    /**
     * Test of prepareMessageAction method, of class
     * DHEServerKeyExchangeHandler.
     */
    @Test
    public void testPrepareMessageRSA() {
        handler.initializeProtocolMessage();
        DHEServerKeyExchangeMessage message = (DHEServerKeyExchangeMessage) handler.getProtocolMessage();

        byte[] result = handler.prepareMessageAction();

        byte[] pTestArray = ArrayConverter
                .hexStringToByteArray("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc"
                        + "74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d"
                        + "51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24"
                        + "117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83"
                        + "655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca1821"
                        + "7c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695"
                        + "5817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff");
        BigInteger pTest = new BigInteger(1, pTestArray);

        assertNotNull("Confirm function didn't return 'NULL'", result);
        assertEquals("Message type must be ServerKeyExchange", HandshakeMessageType.SERVER_KEY_EXCHANGE,
                message.getHandshakeMessageType());
        assertEquals("p length must be 256", new Integer(256), message.getSerializedPLength().getValue());
        assertEquals("p must be pTest", pTest, message.getP().getValue());
        assertEquals("g length must be 1", new Integer(1), message.getSerializedGLength().getValue());
        assertEquals("g must be 2", new BigInteger("2"), message.getG().getValue());
        assertEquals("Public key length is 256", new Integer(256), message.getSerializedPublicKeyLength().getValue());
        assertEquals("Hash must be SHA1", HashAlgorithm.SHA1,
                HashAlgorithm.getHashAlgorithm(message.getHashAlgorithm().getValue()));
        assertEquals("Signature must be RSA", SignatureAlgorithm.RSA,
                SignatureAlgorithm.getSignatureAlgorithm(message.getSignatureAlgorithm().getValue()));
        assertEquals("Signature length must be 128", new Integer(128), message.getSignatureLength().getValue());

    }
}
