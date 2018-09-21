/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import java.util.Arrays;
import java.util.Collection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class ServerHelloParserTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("020000480303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f000000"),
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                72,
                                ProtocolVersion.TLS12,
                                ProtocolVersion.TLS12.getValue(),
                                new byte[] { (byte) 0x37, (byte) 0x8f, (byte) 0x93, (byte) 0xcb },
                                ArrayConverter
                                        .hexStringToByteArray("378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01"),
                                32,
                                ArrayConverter
                                        .hexStringToByteArray("0919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10"),
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue(),
                                CompressionMethod.NULL.getValue(), 0 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("0200003603013a40a6187edfd84f419fb68b7ab2aaa83ffb0e88a61c7d741be0467faeaa56f100003500000eff0100010000230000000f000101"),
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                54,
                                ProtocolVersion.TLS10,
                                ProtocolVersion.TLS10.getValue(),
                                new byte[] { (byte) 0x3a, (byte) 0x40, (byte) 0xa6, (byte) 0x18 },
                                ArrayConverter
                                        .hexStringToByteArray("3a40a6187edfd84f419fb68b7ab2aaa83ffb0e88a61c7d741be0467faeaa56f1"),
                                0, new byte[0], CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA.getByteValue(),
                                CompressionMethod.NULL.getValue(), 14 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("020000360302697b9fc9eeba3fc98a15c6c08f3b8818fb1413b95f57679673fe55721872117b00003500000eff0100010000230000000f000101"),
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                54,
                                ProtocolVersion.TLS11,
                                ProtocolVersion.TLS11.getValue(),
                                new byte[] { (byte) 0x69, (byte) 0x7b, (byte) 0x9f, (byte) 0xc9 },
                                ArrayConverter
                                        .hexStringToByteArray("697b9fc9eeba3fc98a15c6c08f3b8818fb1413b95f57679673fe55721872117b"),
                                0, new byte[0], CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA.getByteValue(),
                                CompressionMethod.NULL.getValue(), 14 } });
    }

    private final byte[] message;
    private final byte messageType;
    private final int messageLength;
    private final ProtocolVersion version;
    private final byte[] protocolVersion;
    private final byte[] unixTime;
    private final byte[] random;
    private final int sessionIdLength;
    private final byte[] sessionID;
    private final byte[] selectedCiphersuite;
    private final byte selectedCompression;
    private final Integer extensionLength;

    public ServerHelloParserTest(byte[] message, byte messageType, int messageLength, ProtocolVersion version,
            byte[] protocolVersion, byte[] unixTime, byte[] random, int sessionIdLength, byte[] sessionID,
            byte[] selectedCiphersuite, byte selectedCompression, Integer extensionLength) {
        this.message = message;
        this.messageType = messageType;
        this.messageLength = messageLength;
        this.version = version;
        this.protocolVersion = protocolVersion;
        this.unixTime = unixTime;
        this.random = random;
        this.sessionIdLength = sessionIdLength;
        this.sessionID = sessionID;
        this.selectedCiphersuite = selectedCiphersuite;
        this.selectedCompression = selectedCompression;
        this.extensionLength = extensionLength;
    }

    /**
     * Test of parse method, of class ServerHelloParser.
     */
    @Test
    public void verify() {
        ServerHelloParser parser = new ServerHelloParser(0, message, version);
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
        LOGGER.debug("Complete was:"
                + ArrayConverter.bytesToHexString(helloMessage.getCompleteResultingMessage().getValue()));
        assertArrayEquals(helloMessage.getCompleteResultingMessage().getValue(), message);
        assertTrue(parser.getPointer() == message.length);

    }
}
