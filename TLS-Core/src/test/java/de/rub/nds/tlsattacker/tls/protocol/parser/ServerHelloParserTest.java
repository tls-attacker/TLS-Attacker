/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class ServerHelloParserTest {

    private static final Logger LOGGER = LogManager.getLogger(ServerHelloParserTest.class);

    //The _CUSTOM is used to indicate that message is hand crafted
    private static byte[] TLS12serverHelloWithEmptyExtensionLength = ArrayConverter
            .hexStringToByteArray("020000480303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f000000");
    private static byte[] TLS12serverHelloWithOutExtensionLength_CUSTOM = ArrayConverter
            .hexStringToByteArray("020000460303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f00");

    @Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][]{
            {ArrayConverter.hexStringToByteArray("020000480303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f000000"), HandshakeMessageType.SERVER_HELLO.getValue(), 72, ProtocolVersion.TLS12.getValue(), new byte[]{(byte) 0x37, (byte) 0x8f, (byte) 0x93, (byte) 0xcb}, ArrayConverter.hexStringToByteArray("cafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01"), 32, ArrayConverter.hexStringToByteArray("0919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10"), CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue(), CompressionMethod.NULL.getValue(),  null},
            {ArrayConverter.hexStringToByteArray("020000460303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f00"), HandshakeMessageType.SERVER_HELLO.getValue(), 74, ProtocolVersion.TLS12.getValue(), new byte[]{(byte) 0x37, (byte) 0x8f, (byte) 0x93, (byte) 0xcb}, ArrayConverter.hexStringToByteArray("cafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01"), 32, ArrayConverter.hexStringToByteArray("0919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10"), CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue(), CompressionMethod.NULL.getValue(), 0}});
    }
    private byte[] message;
    private byte messageType;
    private int messageLength;
    private byte[] protocolVersion;
    private byte[] unixTime;
    private byte[] random;
    private int sessionIdLength;
    private byte[] sessionID;
    private byte[] selectedCiphersuite;
    private byte selectedCompression;
    private Integer extensionLength;

    public ServerHelloParserTest(byte[] message, byte messageType, int messageLength, byte[] protocolVersion, byte[] unixTime, byte[] random, int sessionIdLength, byte[] sessionID, byte[] selectedCiphersuite, byte selectedCompression, Integer extensionLength) {
        this.message = message;
        this.messageType = messageType;
        this.messageLength = messageLength;
        this.protocolVersion = protocolVersion;
        this.unixTime = unixTime;
        this.random = random;
        this.sessionIdLength = sessionIdLength;
        this.sessionID = sessionID;
        this.selectedCiphersuite = selectedCiphersuite;
        this.selectedCompression = selectedCompression;
        this.extensionLength = extensionLength;
    }

   

    @Before
    public void setUp() {
    }

    /**
     * Test of parse method, of class ServerHelloMessageParser.
     */
    @Test
    public void verify() {
        ServerHelloMessageParser parser = new ServerHelloMessageParser(0, message);
        ServerHelloMessage helloMessage = parser.parse();
        assertTrue(helloMessage.getType().getValue() == messageType);
        assertTrue(helloMessage.getLength().getValue() == messageLength);
        assertArrayEquals(helloMessage.getProtocolVersion().getValue(), protocolVersion);
        assertArrayEquals(helloMessage.getUnixTime().getValue(), unixTime);
        assertArrayEquals(helloMessage.getRandom().getValue(), random);
        assertTrue(helloMessage.getSessionIdLength().getValue() == sessionIdLength);
        assertArrayEquals(helloMessage.getSessionId().getValue(), sessionID);
        assertArrayEquals(helloMessage.getSelectedCipherSuite().getValue(), selectedCiphersuite);
        assertTrue(helloMessage.getSelectedCompressionMethod().getValue() == selectedCompression);
        if (extensionLength == null) {
            assertNull(helloMessage.getExtensionsLength());
        } else {
            assertTrue(helloMessage.getExtensionsLength().getValue() == extensionLength.intValue());
        }
        LOGGER.debug("Complete should be:" + ArrayConverter.bytesToHexString(message));
        LOGGER.debug("Complete was:" + ArrayConverter.bytesToHexString(helloMessage.getCompleteResultingMessage().getValue()));
        assertArrayEquals(helloMessage.getCompleteResultingMessage().getValue(), message);
        assertTrue(parser.getPointer() == message.length);

    }
}
