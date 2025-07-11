/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class SSL2ClientHelloSerializerTest
        extends AbstractSSL2MessageSerializerTest<
                SSL2ClientHelloMessage, SSL2ClientHelloSerializer> {

    public SSL2ClientHelloSerializerTest() {
        super(
                SSL2ClientHelloMessage::new,
                SSL2ClientHelloSerializer::new,
                List.of(
                        (msg, obj) -> msg.setType((byte) obj),
                        (msg, obj) -> msg.setMessageLength((Integer) obj),
                        (msg, obj) -> msg.setProtocolVersion((byte[]) obj),
                        (msg, obj) -> msg.setCipherSuiteLength((int) obj),
                        (msg, obj) -> msg.setSessionIDLength((int) obj),
                        (msg, obj) -> msg.setChallengeLength((int) obj),
                        (msg, obj) -> msg.setCipherSuites((byte[]) obj),
                        (msg, obj) -> msg.setSessionID((byte[]) obj),
                        (msg, obj) -> msg.setChallenge((byte[]) obj),
                        (msg, obj) -> msg.setPaddingLength((Integer) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                // Test vector 1: Simple ClientHello with 3 cipher suites and 16-byte challenge
                Arguments.of(
                        ProtocolVersion.SSL2,
                        DataConverter.hexStringToByteArray(
                                "801c" // Message length (28 bytes) with MSB set
                                        + "01" // Message type (CLIENT_HELLO)
                                        + "0002" // Protocol version (SSL 2.0)
                                        + "0009" // Cipher suite length (9 bytes = 3 cipher suites)
                                        + "0000" // Session ID length (0)
                                        + "0010" // Challenge length (16 bytes)
                                        + "010080" // Cipher suite 1: SSL_CK_RC4_128_WITH_MD5
                                        + "020080" // Cipher suite 2:
                                        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
                                        + "030080" // Cipher suite 3: SSL_CK_RC2_128_CBC_WITH_MD5
                                        + "" // No session ID
                                        + "0123456789abcdef0123456789abcdef"), // 16-byte challenge
                        Arrays.asList(
                                SSL2MessageType.SSL_CLIENT_HELLO.getType(),
                                28,
                                DataConverter.hexStringToByteArray("0002"),
                                9,
                                0,
                                16,
                                DataConverter.hexStringToByteArray("010080020080030080"),
                                new byte[0],
                                DataConverter.hexStringToByteArray(
                                        "0123456789abcdef0123456789abcdef"),
                                0)),
                // Test vector 2: ClientHello with session ID and longer challenge
                Arguments.of(
                        ProtocolVersion.SSL2,
                        DataConverter.hexStringToByteArray(
                                "8034" // Message length (52 bytes) with MSB set
                                        + "01" // Message type (CLIENT_HELLO)
                                        + "0002" // Protocol version (SSL 2.0)
                                        + "0006" // Cipher suite length (6 bytes = 2 cipher suites)
                                        + "0010" // Session ID length (16 bytes)
                                        + "0020" // Challenge length (32 bytes)
                                        + "010080" // Cipher suite 1: SSL_CK_RC4_128_WITH_MD5
                                        + "060040" // Cipher suite 2: SSL_CK_DES_64_CBC_WITH_MD5
                                        + "fedcba9876543210fedcba9876543210" // 16-byte session ID
                                        + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), // 32-byte challenge
                        Arrays.asList(
                                SSL2MessageType.SSL_CLIENT_HELLO.getType(),
                                52,
                                DataConverter.hexStringToByteArray("0002"),
                                6,
                                16,
                                32,
                                DataConverter.hexStringToByteArray("010080060040"),
                                DataConverter.hexStringToByteArray(
                                        "fedcba9876543210fedcba9876543210"),
                                DataConverter.hexStringToByteArray(
                                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                                0)));
    }
}
