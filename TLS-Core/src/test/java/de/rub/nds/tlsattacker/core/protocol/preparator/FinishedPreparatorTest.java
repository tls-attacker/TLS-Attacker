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
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class FinishedPreparatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void registerPreviousMessages(TlsContext context, String... handshakeMessageHex) {
        for (String hex : handshakeMessageHex) {
            byte[] bytes = ArrayConverter.hexStringToByteArray(hex);
            context.getDigest().append(bytes);
        }
    }

    private FinishedMessage message;
    private TlsContext context;
    private FinishedPreparator preparator;

    @Before
    public void setUp() {
        message = new FinishedMessage();
        context = new TlsContext();
        preparator = new FinishedPreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * FinishedPreparator.
     */
    @Test
    public void testPrepare() {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        context.setPrfAlgorithm(PRFAlgorithm.TLS_PRF_SHA256);
        preparator.prepare();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getVerifyData().getValue(), false));
        // TODO Did not check if this is calculated correctly, just made sure it
        // is set
        assertArrayEquals(ArrayConverter.hexStringToByteArray("232A2CCB976E313AAA8E0F7A"), message.getVerifyData()
                .getValue());
    }

    @Test
    public void testPrepareAndCompareWithRealDataNullEncrypted() {
        String clientHelloHex = "0100005a0303a0cc405d6b7ee21942c74223e74c1de5935c1390ea0994a010cd8d0853fc2c87000004003b00ff0100002d00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101";
        String serverHelloHex = "0200003603032d6ffc07dec6dd97718b8d82b165f02503e6103f09ae93a0e1f83f2f3e8880ad00003b00000eff0100010000230000000f000101";
        String certificateHex = "0b00028000027d00027a30820276308201dfa003020102020438918374300d06092a864886f70d01010b0500306e3110300e06035504061307556e6b6e6f776e3110300e06035504081307556e6b6e6f776e3110300e06035504071307556e6b6e6f776e3110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e3112301006035504031309616e6f6e796d6f7573301e170d3135303830343133353731375a170d3235303830313133353731375a306e3110300e06035504061307556e6b6e6f776e3110300e06035504081307556e6b6e6f776e3110300e06035504071307556e6b6e6f776e3110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e3112301006035504031309616e6f6e796d6f757330819f300d06092a864886f70d010101050003818d00308189028181008a4ee023df569ce17c504cbb828f16bae5040ccef4b59ef96733dfe34693530d4062f9b4873c72f933607f8ceea01ad2215dab44eaac207f45de5835a8db4e21b35d5e2757f652eaaa25d71a60c37725cddf877427cc9e60e240d0429e708bc4b6017726734b2c03f404d5fea407d91bbe4e86a0ebc685e8078f8657b5830ab30203010001a321301f301d0603551d0e04160414611782c41da8bd62a49ce58580194baa5d8c764f300d06092a864886f70d01010b0500038181005f9708702b8adb185b2db0d05845af5df1f7d13e7a94647a8653187e7a55753f5c19772a994f53136ab04cdad266683bf65a1b78fca418899e44c0e8f75add9df5b432e92a6a0668b16d6278a67c78f8ea30ca587e1dc314d8312d41808284e22df19c7f4bb3086e74b42c9473df8b82449643a4e2fbb05cf8b1b41acec44fe9";
        String serverHelloDoneHex = "0e000000";
        String clientKeyExchangeHex = "1000008200807431f17d9c25a9e56809040950bb7122f3564b3c50ea9537a1b4f57af7350c39c3d6729e098cefa805ad6b5a2079b665980534d0a5dacd9d11e7ff57b224ab0268387a4d4dcbbc460aace7e4d4543249bafed5f2e6bcf22465dde88ab86a198b05090578a6131be51922b8448ca62705131db5f48211147c68c07425c883d7b3";
        String finishedHex = "1400000c0e1e6bd7845c5a971778234b";

        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_NULL_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("E9BBE684A991D223F49A3CBB675B32355A671C8DA5620291FF911D88C0456DC539BEE2C51FA69F1D1C76EF9875E6DA6C"));
        context.setPrfAlgorithm(PRFAlgorithm.TLS_PRF_SHA256);

        registerPreviousMessages(context, clientHelloHex, serverHelloHex, certificateHex, serverHelloDoneHex,
                clientKeyExchangeHex);

        preparator.prepare();

        @SuppressWarnings("unchecked")
        ProtocolMessageHandler<FinishedMessage> handler = message.getHandler(context);
        byte[] protocolMessageBytes = handler.prepareMessage(message);
        Assert.assertArrayEquals(ArrayConverter.hexStringToByteArray(finishedHex), protocolMessageBytes);
    }

    @Test
    public void testPrepareAndCompareWithRealDataNullEncryptedSSLv3() {
        String clientHelloHex = "0100005a0303405e2a60cefcb557edd6d41336a3fa4b2dfdae20f4ac7adacbb29c13456e2800000004000100ff0100002d00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101";
        String serverHelloHex = "020000520300a63cd22a46e4fc22b1f03d579c5f0e43cadfda01ef615fd52a9cdbaed3f6c6c220e019a57851dc08d949a0ffa0c2696f94ca4bd39c1ef3a7ff93708a5bf4510c4c000100000aff01000100000f000101";
        String certificateHex = "0b00028000027d00027a30820276308201dfa003020102020438918374300d06092a864886f70d01010b0500306e3110300e06035504061307556e6b6e6f776e3110300e06035504081307556e6b6e6f776e3110300e06035504071307556e6b6e6f776e3110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e3112301006035504031309616e6f6e796d6f7573301e170d3135303830343133353731375a170d3235303830313133353731375a306e3110300e06035504061307556e6b6e6f776e3110300e06035504081307556e6b6e6f776e3110300e06035504071307556e6b6e6f776e3110300e060355040a1307556e6b6e6f776e3110300e060355040b1307556e6b6e6f776e3112301006035504031309616e6f6e796d6f757330819f300d06092a864886f70d010101050003818d00308189028181008a4ee023df569ce17c504cbb828f16bae5040ccef4b59ef96733dfe34693530d4062f9b4873c72f933607f8ceea01ad2215dab44eaac207f45de5835a8db4e21b35d5e2757f652eaaa25d71a60c37725cddf877427cc9e60e240d0429e708bc4b6017726734b2c03f404d5fea407d91bbe4e86a0ebc685e8078f8657b5830ab30203010001a321301f301d0603551d0e04160414611782c41da8bd62a49ce58580194baa5d8c764f300d06092a864886f70d01010b0500038181005f9708702b8adb185b2db0d05845af5df1f7d13e7a94647a8653187e7a55753f5c19772a994f53136ab04cdad266683bf65a1b78fca418899e44c0e8f75add9df5b432e92a6a0668b16d6278a67c78f8ea30ca587e1dc314d8312d41808284e22df19c7f4bb3086e74b42c9473df8b82449643a4e2fbb05cf8b1b41acec44fe9";
        String serverHelloDoneHex = "0e000000";
        String clientKeyExchangeHex = "100000801a4dc552ddd7e1e25dbaff38dd447b3a6fdc85120e2f760fefdab88e5adbbc710f3d0843f07c9f4f5ac01bc4cea02c4030c272074aa04b1b80a71123b73ea4efbe928b54a83fe4b39472bf66a953c7dc11cfb13ea08f92047996799ce702eb72a7c69bdfd98b91a09bcb836414752d93d3641740f8ed5cfff682225434052230";
        String finishedHex = "14000024ca89059c0d65ae7d5e0c11d99e7de49f830776fa43be27550285015fe254946754b8306f";

        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_NULL_MD5);
        context.setSelectedProtocolVersion(ProtocolVersion.SSL3);
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("91709DA9667796D3B0EFB3C0E920279A5F2EB76F4B9C84E2E89A2A4BF236CB8BE64AAA53CA30A3CF29B563B246DF7FFC"));

        registerPreviousMessages(context, clientHelloHex, serverHelloHex, certificateHex, serverHelloDoneHex,
                clientKeyExchangeHex);

        preparator.prepare();

        @SuppressWarnings("unchecked")
        ProtocolMessageHandler<FinishedMessage> handler = message.getHandler(context);
        byte[] protocolMessageBytes = handler.prepareMessage(message);
        Assert.assertEquals(ArrayConverter.hexStringToByteArray(finishedHex).length, protocolMessageBytes.length);
        Assert.assertArrayEquals(ArrayConverter.hexStringToByteArray(finishedHex), protocolMessageBytes);
    }

    /**
     * Test of prepareHandshakeMessageContents method for TLS 1.3, of class
     * FinishedPreparator.
     */
    @Test
    public void testPrepareTLS13() {
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setConnection(new OutboundConnection());
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("2E9C9DD264A15D3C1EEC604A7C862934486764F94E35C0BA7E0B9494EAC06E82"));
        context.getDigest().setRawBytes(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"));
        preparator.prepare();
        assertArrayEquals(message.getVerifyData().getValue(),
                ArrayConverter.hexStringToByteArray("B4AB5C21316FD38E3605D62C9022062DA84D83214EBC7BCD4BE6B3DB1971AFCA"));
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
