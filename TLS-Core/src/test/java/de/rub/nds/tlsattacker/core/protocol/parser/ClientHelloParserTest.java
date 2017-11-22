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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ClientHelloParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("010000780303a9b0b601d3dd7d8cfcc2ef56d3b6130bf523fe5d009780088ff1227c10bcaf66000022009d003d00350084009c003c002f00960041000700050004000a003b0002000100ff0100002d00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101"),
                                HandshakeMessageType.CLIENT_HELLO,
                                0x78,
                                ProtocolVersion.TLS12,
                                ProtocolVersion.TLS12.getValue(),
                                ArrayConverter.hexStringToByteArray("a9b0b601"),
                                ArrayConverter
                                        .hexStringToByteArray("a9b0b601d3dd7d8cfcc2ef56d3b6130bf523fe5d009780088ff1227c10bcaf66"),
                                0,
                                new byte[0],
                                34,
                                ArrayConverter
                                        .hexStringToByteArray("009d003d00350084009c003c002f00960041000700050004000a003b0002000100ff"),
                                1,
                                new byte[] { 0 },
                                45,
                                ArrayConverter
                                        .hexStringToByteArray("00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101"),
                                null, null, 3 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("010000be030227169c1bfddc2cce7990edcdf5555dad8a8e73451a87745c305e645cd9f0578c000064c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000031000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                                HandshakeMessageType.CLIENT_HELLO,
                                0x00be,
                                ProtocolVersion.TLS11,
                                ProtocolVersion.TLS11.getValue(),
                                ArrayConverter.hexStringToByteArray("27169c1b"),
                                ArrayConverter
                                        .hexStringToByteArray("27169c1bfddc2cce7990edcdf5555dad8a8e73451a87745c305e645cd9f0578c"),
                                0,
                                new byte[0],
                                100,
                                ArrayConverter
                                        .hexStringToByteArray("c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff"),
                                1,
                                new byte[] { 0 },
                                49,
                                ArrayConverter
                                        .hexStringToByteArray("000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                                null, null, 4 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("010000be0301e6e95eb287b80d868b6ca3aafad6912e21bf71b6bbcabb1fcc46516abb162e3b000064c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000031000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                                HandshakeMessageType.CLIENT_HELLO,
                                0x00be,
                                ProtocolVersion.TLS10,
                                ProtocolVersion.TLS10.getValue(),
                                ArrayConverter.hexStringToByteArray("e6e95eb2"),
                                ArrayConverter
                                        .hexStringToByteArray("e6e95eb287b80d868b6ca3aafad6912e21bf71b6bbcabb1fcc46516abb162e3b"),
                                0,
                                new byte[0],
                                100,
                                ArrayConverter
                                        .hexStringToByteArray("c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff"),
                                1,
                                new byte[] { 0 },
                                49,
                                ArrayConverter
                                        .hexStringToByteArray("000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                                null, null, 4 } });
    }

    private final byte[] message;

    private final ProtocolVersion version;
    private final HandshakeMessageType type;
    private final int length;
    private final byte[] protocolVersion;
    private final byte[] unixtime;
    private final byte[] random;
    private final int sessionIdLength;
    private final byte[] sessionID;
    private final int cipherSuitesLength;
    private final byte[] cipherSuites;
    private final int compressionsLength;
    private final byte[] compressions;
    private final Integer extensionLength;
    private final byte[] extensionBytes;
    private final Byte cookieLength;
    private final byte[] cookie;
    private final int numberOfExtensions;

    public ClientHelloParserTest(byte[] message, HandshakeMessageType type, int length, ProtocolVersion version,
            byte[] protocolVersion, byte[] unixtime, byte[] random, int sessionIdLength, byte[] sessionID,
            int cipherSuitesLength, byte[] cipherSuites, int compressionsLength, byte[] compressions,
            Integer extensionLength, byte[] extensionBytes, Byte cookieLength, byte[] cookie, int numberOfExtensions) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.version = version;
        this.protocolVersion = protocolVersion;
        this.unixtime = unixtime;
        this.random = random;
        this.sessionIdLength = sessionIdLength;
        this.sessionID = sessionID;
        this.cipherSuitesLength = cipherSuitesLength;
        this.cipherSuites = cipherSuites;
        this.compressionsLength = compressionsLength;
        this.compressions = compressions;
        this.extensionLength = extensionLength;
        this.extensionBytes = extensionBytes;
        this.cookieLength = cookieLength;
        this.cookie = cookie;
        this.numberOfExtensions = numberOfExtensions;
    }

    /**
     * Test of parse method, of class ClientHelloParser.
     */
    @Test
    public void testParse() {
        ClientHelloParser parser = new ClientHelloParser(0, message, version);
        ClientHelloMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertArrayEquals(cipherSuites, msg.getCipherSuites().getValue());
        assertArrayEquals(compressions, msg.getCompressions().getValue());
        assertArrayEquals(sessionID, msg.getSessionId().getValue());
        assertArrayEquals(random, msg.getRandom().getValue());
        assertArrayEquals(unixtime, msg.getUnixTime().getValue());
        assertArrayEquals(protocolVersion, msg.getProtocolVersion().getValue());
        if (cookie != null) {
            assertArrayEquals(cookie, msg.getCookie().getValue());
        } else {
            assertNull(msg.getCookie());
        }

        if (extensionLength != null) {
            assertTrue(Objects.equals(extensionLength, msg.getExtensionsLength().getValue()));
        } else {
            assertNull(msg.getExtensionsLength());
        }

        if (extensionBytes != null) {
            assertArrayEquals(extensionBytes, msg.getExtensionBytes().getValue());
        } else {
            assertNull(msg.getExtensionBytes());
        }

        if (cookieLength != null) {
            assertTrue(cookieLength == msg.getCookieLength().getValue().byteValue());
        } else {
            assertNull(msg.getCookieLength());
        }
        assertTrue(cipherSuitesLength == msg.getCipherSuiteLength().getValue());
        assertTrue(compressionsLength == msg.getCompressionLength().getValue());
        assertTrue(sessionIdLength == msg.getSessionIdLength().getValue());
        assertTrue(numberOfExtensions == msg.getExtensions().size());
    }
}
