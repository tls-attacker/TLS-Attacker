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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownSSL2Message;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class UnknownSSL2MessageSerializerTest
        extends AbstractSSL2MessageSerializerTest<
                UnknownSSL2Message, UnknownSSL2MessageSerializer> {

    public UnknownSSL2MessageSerializerTest() {
        super(
                UnknownSSL2Message::new,
                UnknownSSL2MessageSerializer::new,
                List.of(
                        (msg, obj) -> msg.setType((byte) obj),
                        (msg, obj) -> msg.setMessageLength((Integer) obj),
                        (msg, obj) -> msg.setCompleteResultingMessage((byte[]) obj),
                        (msg, obj) -> msg.setPaddingLength((Integer) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                // Test vector 1: Unknown message with type 0xFF
                Arguments.of(
                        ProtocolVersion.SSL2,
                        DataConverter.hexStringToByteArray(
                                "8010" // Message length (16 bytes) with MSB set
                                        + "ff" // Message type (0xFF - unknown)
                                        + "0123456789abcdef0123456789abcdef"), // 16-byte message
                        // body
                        Arrays.asList(
                                (byte) 0xff,
                                16,
                                DataConverter.hexStringToByteArray(
                                        "0123456789abcdef0123456789abcdef"),
                                0)),
                // Test vector 2: Unknown message with type 0x99 and longer data
                Arguments.of(
                        ProtocolVersion.SSL2,
                        DataConverter.hexStringToByteArray(
                                "8020" // Message length (32 bytes) with MSB set
                                        + "99" // Message type (0x99 - unknown)
                                        + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), // 32-byte message body
                        Arrays.asList(
                                (byte) 0x99,
                                32,
                                DataConverter.hexStringToByteArray(
                                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                                0)),
                // Test vector 3: Unknown message with minimal data
                Arguments.of(
                        ProtocolVersion.SSL2,
                        DataConverter.hexStringToByteArray(
                                "8004" // Message length (4 bytes) with MSB set
                                        + "aa" // Message type (0xAA - unknown)
                                        + "deadbeef"), // 4-byte message body
                        Arrays.asList(
                                (byte) 0xaa, 4, DataConverter.hexStringToByteArray("deadbeef"), 0)),
                // Test vector 4: Unknown message with empty body (just header)
                Arguments.of(
                        ProtocolVersion.SSL2,
                        DataConverter.hexStringToByteArray(
                                "8000" // Message length (0 bytes) with MSB set
                                        + "bb"), // Message type (0xBB - unknown)
                        Arrays.asList((byte) 0xbb, 0, new byte[0], 0)));
    }
}
