/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class SSL2ServerHelloSerializerTest
        extends AbstractSSL2MessageSerializerTest<
                SSL2ServerHelloMessage, SSL2ServerHelloSerializer> {

    public SSL2ServerHelloSerializerTest() {
        super(
                SSL2ServerHelloMessage::new,
                SSL2ServerHelloSerializer::new,
                List.of(
                        (msg, obj) -> msg.setType((byte) obj),
                        (msg, obj) -> msg.setMessageLength((Integer) obj),
                        (msg, obj) -> msg.setSessionIdHit((byte) obj),
                        (msg, obj) -> msg.setCertificateType((byte) obj),
                        (msg, obj) -> msg.setProtocolVersion((byte[]) obj),
                        (msg, obj) -> msg.setCertificateLength((int) obj),
                        (msg, obj) -> msg.setCipherSuitesLength((int) obj),
                        (msg, obj) -> msg.setSessionIDLength((int) obj),
                        (msg, obj) -> msg.setCertificate((byte[]) obj),
                        (msg, obj) -> msg.setCipherSuites((byte[]) obj),
                        (msg, obj) -> msg.setSessionID((byte[]) obj),
                        (msg, obj) -> msg.setPaddingLength((Integer) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                // Test vector 1: Simple ServerHello without session ID hit
                Arguments.of(
                        ProtocolVersion.SSL2,
                        ArrayConverter.hexStringToByteArray(
                                "802e" // Message length (46 bytes) with MSB set
                                        + "04" // Message type (SERVER_HELLO)
                                        + "00" // Session ID hit (0 = false)
                                        + "01" // Certificate type (1 = X.509)
                                        + "0002" // Protocol version (SSL 2.0)
                                        + "0020" // Certificate length (32 bytes)
                                        + "0003" // Cipher suites length (3 bytes = 1 cipher suite)
                                        + "0010" // Session ID length (16 bytes)
                                        + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 32-byte certificate (dummy)
                                        + "010080" // Cipher suite: SSL_CK_RC4_128_WITH_MD5
                                        + "fedcba9876543210fedcba9876543210"), // 16-byte session ID
                        Arrays.asList(
                                SSL2MessageType.SSL_SERVER_HELLO.getType(),
                                46,
                                (byte) 0x00,
                                (byte) 0x01,
                                ArrayConverter.hexStringToByteArray("0002"),
                                32,
                                3,
                                16,
                                ArrayConverter.hexStringToByteArray(
                                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                                ArrayConverter.hexStringToByteArray("010080"),
                                ArrayConverter.hexStringToByteArray(
                                        "fedcba9876543210fedcba9876543210"),
                                0)),
                // Test vector 2: ServerHello with session ID hit (no certificate)
                Arguments.of(
                        ProtocolVersion.SSL2,
                        ArrayConverter.hexStringToByteArray(
                                "801a" // Message length (26 bytes) with MSB set
                                        + "04" // Message type (SERVER_HELLO)
                                        + "01" // Session ID hit (1 = true)
                                        + "00" // Certificate type (0 = none, since session hit)
                                        + "0002" // Protocol version (SSL 2.0)
                                        + "0000" // Certificate length (0 bytes)
                                        + "0003" // Cipher suites length (3 bytes = 1 cipher suite)
                                        + "0010" // Session ID length (16 bytes)
                                        + "" // No certificate
                                        + "060040" // Cipher suite: SSL_CK_DES_64_CBC_WITH_MD5
                                        + "1234567890abcdef1234567890abcdef"), // 16-byte session ID
                        Arrays.asList(
                                SSL2MessageType.SSL_SERVER_HELLO.getType(),
                                26,
                                (byte) 0x01,
                                (byte) 0x00,
                                ArrayConverter.hexStringToByteArray("0002"),
                                0,
                                3,
                                16,
                                new byte[0],
                                ArrayConverter.hexStringToByteArray("060040"),
                                ArrayConverter.hexStringToByteArray(
                                        "1234567890abcdef1234567890abcdef"),
                                0)),
                // Test vector 3: ServerHello with multiple cipher suites
                Arguments.of(
                        ProtocolVersion.SSL2,
                        ArrayConverter.hexStringToByteArray(
                                "8023" // Message length (35 bytes) with MSB set
                                        + "04" // Message type (SERVER_HELLO)
                                        + "00" // Session ID hit (0 = false)
                                        + "01" // Certificate type (1 = X.509)
                                        + "0002" // Protocol version (SSL 2.0)
                                        + "0010" // Certificate length (16 bytes)
                                        + "0009" // Cipher suites length (9 bytes = 3 cipher suites)
                                        + "0008" // Session ID length (8 bytes)
                                        + "0123456789abcdef0123456789abcdef" // 16-byte certificate
                                        // (dummy)
                                        + "010080" // Cipher suite 1: SSL_CK_RC4_128_WITH_MD5
                                        + "020080" // Cipher suite 2:
                                        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
                                        + "030080" // Cipher suite 3: SSL_CK_RC2_128_CBC_WITH_MD5
                                        + "fedcba9876543210"), // 8-byte session ID
                        Arrays.asList(
                                SSL2MessageType.SSL_SERVER_HELLO.getType(),
                                35,
                                (byte) 0x00,
                                (byte) 0x01,
                                ArrayConverter.hexStringToByteArray("0002"),
                                16,
                                9,
                                8,
                                ArrayConverter.hexStringToByteArray(
                                        "0123456789abcdef0123456789abcdef"),
                                ArrayConverter.hexStringToByteArray("010080020080030080"),
                                ArrayConverter.hexStringToByteArray("fedcba9876543210"),
                                0)));
    }
}
