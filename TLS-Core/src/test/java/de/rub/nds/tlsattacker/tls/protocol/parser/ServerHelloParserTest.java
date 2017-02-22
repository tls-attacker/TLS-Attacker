/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerHelloParserTest {

    private static final Logger LOGGER = LogManager.getLogger(ServerHelloParserTest.class);
    
    //The _CUSTOM is used to indicate that message is hand crafted
    private static byte[] TLS12serverHelloWithEmptyExtensionLength = ArrayConverter
            .hexStringToByteArray("020000480303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f000000");
    private static byte[] TLS12serverHelloWithOutExtensionLength_CUSTOM = ArrayConverter
            .hexStringToByteArray("020000460303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f00");

    public ServerHelloParserTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of parse method, of class ServerHelloParser.
     */
    @Test
    public void testParseServerHelloWithEmptyExtensionLength() {
        LOGGER.debug("Parsing with 00 00 extension length field");
        ServerHelloParser parser = new ServerHelloParser(0, TLS12serverHelloWithEmptyExtensionLength);
        ServerHelloMessage message = parser.parse();
        assertTrue(message.getType().getValue() == HandshakeMessageType.SERVER_HELLO.getValue());
        assertTrue(message.getLength().getValue() == 72);
        assertArrayEquals(message.getProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
        assertArrayEquals(message.getUnixTime().getValue(), new byte[]{(byte) 0x37, (byte) 0x8f, (byte) 0x93, (byte) 0xcb});
        assertArrayEquals(message.getRandom().getValue(),ArrayConverter.hexStringToByteArray("cafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01"));
        assertTrue(message.getSessionIdLength().getValue() == 32);
        assertArrayEquals(message.getSessionId().getValue(),ArrayConverter.hexStringToByteArray("0919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10"));
        assertArrayEquals(message.getSelectedCipherSuite().getValue(),CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue());
        assertTrue(message.getSelectedCompressionMethod().getValue() == CompressionMethod.NULL.getValue());
        //assertTrue(message.getExtensionsLength().getValue() == 0);
        LOGGER.debug("Complete should be:"+ArrayConverter.bytesToHexString(TLS12serverHelloWithEmptyExtensionLength));
        LOGGER.debug("Complete was:"+ArrayConverter.bytesToHexString(message.getCompleteResultingMessage().getValue()));
        assertArrayEquals(message.getCompleteResultingMessage().getValue(), TLS12serverHelloWithEmptyExtensionLength);
        assertTrue(parser.getPointer() == TLS12serverHelloWithEmptyExtensionLength.length);
        
    }

    /**
     * Test of parse method, of class ServerHelloParser.
     */
    @Test
    public void testParseServerHelloWithoutExtensionLength() {
        LOGGER.debug("Parsing without extension length field");
        ServerHelloParser parser = new ServerHelloParser(0, TLS12serverHelloWithOutExtensionLength_CUSTOM);
        ServerHelloMessage message = parser.parse();
        assertTrue(message.getType().getValue() == HandshakeMessageType.SERVER_HELLO.getValue());
        assertTrue(message.getLength().getValue() == 70);
        assertArrayEquals(message.getProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
        assertArrayEquals(message.getUnixTime().getValue(), new byte[]{(byte) 0x37, (byte) 0x8f, (byte) 0x93, (byte) 0xcb});
        assertArrayEquals(message.getRandom().getValue(),ArrayConverter.hexStringToByteArray("cafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01"));
        assertTrue(message.getSessionIdLength().getValue() == 32);
        assertArrayEquals(message.getSessionId().getValue(),ArrayConverter.hexStringToByteArray("0919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10"));
        assertArrayEquals(message.getSelectedCipherSuite().getValue(),CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue());
        assertTrue(message.getSelectedCompressionMethod().getValue() == CompressionMethod.NULL.getValue());
        LOGGER.debug("Complete should be:"+ArrayConverter.bytesToHexString(TLS12serverHelloWithOutExtensionLength_CUSTOM));
        LOGGER.debug("Complete was:"+ArrayConverter.bytesToHexString(message.getCompleteResultingMessage().getValue()));
        assertArrayEquals(message.getCompleteResultingMessage().getValue(), TLS12serverHelloWithOutExtensionLength_CUSTOM);
        assertTrue(parser.getPointer() == TLS12serverHelloWithOutExtensionLength_CUSTOM.length);
    }

}
