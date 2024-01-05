/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;

public class ClientHelloParserTest
        extends AbstractHandshakeMessageParserTest<ClientHelloMessage, ClientHelloParser> {

    public ClientHelloParserTest() {
        super(
                ClientHelloMessage.class,
                ClientHelloParser::new,
                List.of(
                        Named.of(
                                "HelloMessage::getProtocolVersion",
                                HelloMessage::getProtocolVersion),
                        Named.of("HelloMessage::getUnixTime", HelloMessage::getUnixTime),
                        Named.of("HelloMessage::getRandom", HelloMessage::getRandom),
                        Named.of(
                                "HelloMessage::getSessionIdLength",
                                HelloMessage::getSessionIdLength),
                        Named.of("HelloMessage::getSessionId", HelloMessage::getSessionId),
                        Named.of(
                                "ClientHelloMessage::getCipherSuiteLength",
                                ClientHelloMessage::getCipherSuiteLength),
                        Named.of(
                                "ClientHelloMessage::getCipherSuites",
                                ClientHelloMessage::getCipherSuites),
                        Named.of(
                                "ClientHelloMessage::getCompressionLength",
                                ClientHelloMessage::getCompressionLength),
                        Named.of(
                                "ClientHelloMessage::getCompressions",
                                ClientHelloMessage::getCompressions),
                        Named.of(
                                "HelloMessage::getExtensionsLength",
                                HelloMessage::getExtensionsLength),
                        Named.of(
                                "HelloMessage::getExtensionBytes", HelloMessage::getExtensionBytes),
                        Named.of(
                                "HelloMessage::getExtensions::size",
                                (msg) -> msg.getExtensions().size()),
                        Named.of(
                                "ClientHelloMessage::getCookieLength",
                                ClientHelloMessage::getCookieLength),
                        Named.of("ClientHelloMessage::getCookie", ClientHelloMessage::getCookie)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "010000780303a9b0b601d3dd7d8cfcc2ef56d3b6130bf523fe5d009780088ff1227c10bcaf66000022009d003d00350084009c003c002f00960041000700050004000a003b0002000100ff0100002d00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101"),
                        Arrays.asList(
                                HandshakeMessageType.CLIENT_HELLO.getValue(),
                                0x78,
                                ProtocolVersion.TLS12.getValue(),
                                ArrayConverter.hexStringToByteArray("a9b0b601"),
                                ArrayConverter.hexStringToByteArray(
                                        "a9b0b601d3dd7d8cfcc2ef56d3b6130bf523fe5d009780088ff1227c10bcaf66"),
                                0,
                                new byte[0],
                                34,
                                ArrayConverter.hexStringToByteArray(
                                        "009d003d00350084009c003c002f00960041000700050004000a003b0002000100ff"),
                                1,
                                new byte[] {0},
                                45,
                                ArrayConverter.hexStringToByteArray(
                                        "00230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101"),
                                3,
                                null,
                                null)),
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray(
                                "010000be030227169c1bfddc2cce7990edcdf5555dad8a8e73451a87745c305e645cd9f0578c000064c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000031000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                        Arrays.asList(
                                HandshakeMessageType.CLIENT_HELLO.getValue(),
                                0x00be,
                                ProtocolVersion.TLS11.getValue(),
                                ArrayConverter.hexStringToByteArray("27169c1b"),
                                ArrayConverter.hexStringToByteArray(
                                        "27169c1bfddc2cce7990edcdf5555dad8a8e73451a87745c305e645cd9f0578c"),
                                0,
                                new byte[0],
                                100,
                                ArrayConverter.hexStringToByteArray(
                                        "c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff"),
                                1,
                                new byte[] {0},
                                49,
                                ArrayConverter.hexStringToByteArray(
                                        "000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                                4,
                                null,
                                null)),
                Arguments.of(
                        ProtocolVersion.TLS10,
                        ArrayConverter.hexStringToByteArray(
                                "010000be0301e6e95eb287b80d868b6ca3aafad6912e21bf71b6bbcabb1fcc46516abb162e3b000064c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff01000031000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                        Arrays.asList(
                                HandshakeMessageType.CLIENT_HELLO.getValue(),
                                0x00be,
                                ProtocolVersion.TLS10.getValue(),
                                ArrayConverter.hexStringToByteArray("e6e95eb2"),
                                ArrayConverter.hexStringToByteArray(
                                        "e6e95eb287b80d868b6ca3aafad6912e21bf71b6bbcabb1fcc46516abb162e3b"),
                                0,
                                new byte[0],
                                100,
                                ArrayConverter.hexStringToByteArray(
                                        "c014c00a00390038003700360088008700860085c00fc00500350084c013c0090033003200310030009a0099009800970045004400430042c00ec004002f009600410007c011c007c00cc00200050004c012c008001600130010000dc00dc003000a00ff"),
                                1,
                                new byte[] {0},
                                49,
                                ArrayConverter.hexStringToByteArray(
                                        "000b000403000102000a001c001a00170019001c001b0018001a0016000e000d000b000c0009000a00230000000f000101"),
                                4,
                                null,
                                null)));
    }

    @Test
    public void testClientHelloMessageLengthTooShort() {
        ClientHelloParser parser =
                new ClientHelloParser(
                        new ByteArrayInputStream(
                                ArrayConverter.hexStringToByteArray(
                                        "010000640303D247A8EE60B420BB3851D9D47ACB933DBE70399BF6C92DA33AF01D4FB770E98C00025A000A002F00010002003C003D00350041008400070009009600040005C09CC09D009C009D000D001000130016001700190018001A001B003000310032003300340036003700380039003AC003C004C005C008C009C00AC00DC00EC00FC012C013C014C027C024C02800A100A000A500A600A7009E009F0067006B006C006D0015C09EC09F009A0045008800A200A30066C031C032C011C02FC030C02DC02EC02BC02CC0ACC0AD13011302008CC0AAC0ABC0AB008B00AEC0A4C0A800A8008D00AFC0A5C0A900A9008A008F0090C0A600AA009100B3C0A700AB008EC034C035C023C036C038C033000F003F004300480049004A0068006900860092009300940095009800AC00AD00B200B600B700BA00BC00BE00C000C200C4C002C007C00CC015C01DC020C025C026C029C02AC037C03CC03DC048C049C04AC04BC04CC04DC04EC04FC050C051C052C053C054C055C05CC05DC05EC05FC060C061C062C063C064C065C066C067C068C069C06AC06BC06CC06DC06EC06FC070C071C072C073C074C075C076C077C078C079C07AC07BC07CC07DC07EC07FC086C087C088C089C08AC08BC08CC08DC08EC08FC090C091C092C093C094C095C096C097C098C099C09AC09B002C002D002E003B004700B000B100B400B500B800B9C001C006C00BC010C039C03AC03B000C0012003E0040004200440046005700580059005A006A00850087008900970099009B00A400BB00BD00BF00C100C300C5C016C017C018C019C03EC03FC040C041C042C043C044C045C046C047C056C057C058C059C05AC05BC080C081C082C083C084C08500810083FF85FF87CCAACCA9CCA801000000")),
                        tlsContext);
        ClientHelloMessage clientHello = new ClientHelloMessage();
        EndOfStreamException exception =
                assertThrows(EndOfStreamException.class, () -> parser.parse(clientHello));
        assertEquals("Reached end of stream after 427 bytes", exception.getMessage());
    }
}
