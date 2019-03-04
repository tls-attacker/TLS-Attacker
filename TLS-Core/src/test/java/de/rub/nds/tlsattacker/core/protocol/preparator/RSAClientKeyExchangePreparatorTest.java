/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class RSAClientKeyExchangePreparatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private TlsContext context;
    private RSAClientKeyExchangePreparator preparator;
    private RSAClientKeyExchangeMessage message;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new RSAClientKeyExchangeMessage();
        preparator = new RSAClientKeyExchangePreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * RSAClientKeyExchangePreparator.
     */
    @Test
    public void testPrepare() {
        // TODO
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        context.setServerRandom(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        // Test
        preparator.prepareHandshakeMessageContents();
        assertArrayEquals(
                ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"),
                        ArrayConverter.hexStringToByteArray("AABBCCDDEEFF")), message.getComputations()
                        .getClientServerRandom().getValue());
        assertNotNull(message.getComputations().getPremasterSecret().getValue());
        assertEquals(HandshakeByteLength.PREMASTER_SECRET,
                message.getComputations().getPremasterSecret().getValue().length);
        assertEquals(ProtocolVersion.TLS12.getMajor(), message.getComputations().getPremasterSecret().getValue()[0]);
        assertEquals(ProtocolVersion.TLS12.getMinor(), message.getComputations().getPremasterSecret().getValue()[1]);
        assertNotNull(message.getComputations().getPlainPaddedPremasterSecret().getValue());
        // Check correct pkcs1 format
        assertEquals((byte) 0x00, message.getComputations().getPlainPaddedPremasterSecret().getValue()[0]);
        assertEquals((byte) 0x02, message.getComputations().getPlainPaddedPremasterSecret().getValue()[1]);
        assertEquals((byte) 0x00, message.getComputations().getPlainPaddedPremasterSecret().getValue()[message
                .getComputations().getPadding().getValue().length + 2]);
        assertNotNull(message.getPublicKeyLength().getValue());
        assertNotNull(message.getPublicKey());
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH), bytesToParse));
            return Certificate.parse(stream);
        } catch (IOException E) {
            LOGGER.warn("Could not parse Certificate bytes into Certificate object:"
                    + ArrayConverter.bytesToHexString(bytesToParse, false));
            return null;
        }
    }

    @Test
    public void testPrepareSSL3() throws IOException {

        CertificateMessage certmessage = new CertificateMessage();
        certmessage
                .setCertificatesListBytes(ArrayConverter
                        .hexStringToByteArray("00027a30820276308201dfa003020102020438918374300d06092a864886f70d01010b0500306e3110300e06035504061307556e6b6e6f776e3110300e06035504081307556e6b6e6f776e3110300e06035504071307556e6b6e6f776e3110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e3112301006035504031309616e6f6e796d6f7573301e170d3135303830343133353731375a170d3235303830313133353731375a306e3110300e06035504061307556e6b6e6f776e3110300e06035504081307556e6b6e6f776e3110300e06035504071307556e6b6e6f776e3110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e3112301006035504031309616e6f6e796d6f757330819f300d06092a864886f70d010101050003818d00308189028181008a4ee023df569ce17c504cbb828f16bae5040ccef4b59ef96733dfe34693530d4062f9b4873c72f933607f8ceea01ad2215dab44eaac207f45de5835a8db4e21b35d5e2757f652eaaa25d71a60c37725cddf877427cc9e60e240d0429e708bc4b6017726734b2c03f404d5fea407d91bbe4e86a0ebc685e8078f8657b5830ab30203010001a321301f301d0603551d0e04160414611782c41da8bd62a49ce58580194baa5d8c764f300d06092a864886f70d01010b0500038181005f9708702b8adb185b2db0d05845af5df1f7d13e7a94647a8653187e7a55753f5c19772a994f53136ab04cdad266683bf65a1b78fca418899e44c0e8f75add9df5b432e92a6a0668b16d6278a67c78f8ea30ca587e1dc314d8312d41808284e22df19c7f4bb3086e74b42c9473df8b82449643a4e2fbb05cf8b1b41acec44fe9"));
        certmessage.setCertificatesListLength(637);
        Security.addProvider(new BouncyCastleProvider());
        CertificateMessageHandler handler = new CertificateMessageHandler(context);
        handler.adjustTLSContext(certmessage);

        Certificate cert = parseCertificate(certmessage.getCertificatesListLength().getValue(), certmessage
                .getCertificatesListBytes().getValue());

        context.setClientRsaModulus(CertificateUtils.extractRSAModulus(cert));
        String preMasterSecret = "1a4dc552ddd7e1e25dbaff38dd447b3a6fdc85120e2f760fefdab88e5adbbc710f3d0843f07c9f4f5ac01bc4cea02c4030c272074aa04b1b80a71123b73ea4efbe928b54a83fe4b39472bf66a953c7dc11cfb13ea08f92047996799ce702eb72a7c69bdfd98b91a09bcb836414752d93d3641740f8ed5cfff682225434052230";
        String keyEx = " 100000801a4dc552ddd7e1e25dbaff38dd447b3a6fdc85120e2f760fefdab88e5adbbc710f3d0843f07c9f4f5ac01bc4cea02c4030c272074aa04b1b80a71123b73ea4efbe928b54a83fe4b39472bf66a953c7dc11cfb13ea08f92047996799ce702eb72a7c69bdfd98b91a09bcb836414752d93d3641740f8ed5cfff682225434052230";
        LOGGER.debug(keyEx.length());
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_NULL_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("405e2a60cefcb557edd6d41336a3fa4b2dfdae20f4ac7adacbb29c13456e2800"));
        LOGGER.debug("405e2a60cefcb557edd6d41336a3fa4b2dfdae20f4ac7adacbb29c13456e2800".length());
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("a63cd22a46e4fc22b1f03d579c5f0e43cadfda01ef615fd52a9cdbaed3f6c6c2"));
        // context.setRsaModulus(CertificateUtils.extractRSAModulus(cert));

        // Test
        preparator.prepareHandshakeMessageContents();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getComputations().getPlainPaddedPremasterSecret(), false));
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
