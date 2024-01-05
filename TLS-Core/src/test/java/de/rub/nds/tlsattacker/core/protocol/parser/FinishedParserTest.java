/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class FinishedParserTest
        extends AbstractHandshakeMessageParserTest<FinishedMessage, FinishedParser> {

    public FinishedParserTest() {
        super(
                FinishedMessage.class,
                FinishedParser::new,
                List.of(
                        Named.of(
                                "FinishedMessage::getVerifyData", FinishedMessage::getVerifyData)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("1400000c001122334455667766554433"),
                        List.of(
                                HandshakeMessageType.FINISHED.getValue(),
                                12,
                                ArrayConverter.hexStringToByteArray("001122334455667766554433"))),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("1400000ccc111ca8d8d84321f1039b92"),
                        List.of(
                                HandshakeMessageType.FINISHED.getValue(),
                                12,
                                ArrayConverter.hexStringToByteArray("cc111ca8d8d84321f1039b92"))),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("1400000c5ddfb413e7b592b4ec0186c5"),
                        List.of(
                                HandshakeMessageType.FINISHED.getValue(),
                                12,
                                ArrayConverter.hexStringToByteArray("5ddfb413e7b592b4ec0186c5"))),
                Arguments.of(
                        ProtocolVersion.SSL3,
                        ArrayConverter.hexStringToByteArray(
                                "14000024ca89059c0d65ae7d5e0c11d99e7de49f830776fa43be27550285015fe254946754b8306f"),
                        List.of(
                                HandshakeMessageType.FINISHED.getValue(),
                                36,
                                ArrayConverter.hexStringToByteArray(
                                        "ca89059c0d65ae7d5e0c11d99e7de49f830776fa43be27550285015fe254946754b8306f"))),
                Arguments.of(
                        ProtocolVersion.SSL3,
                        ArrayConverter.hexStringToByteArray(
                                "14000024d9f3911c7cd84b44bd3aa9fa730fc9883fdadfa90ac7e7d1c68fa7ef19749f263c3a1811"),
                        List.of(
                                HandshakeMessageType.FINISHED.getValue(),
                                36,
                                ArrayConverter.hexStringToByteArray(
                                        "d9f3911c7cd84b44bd3aa9fa730fc9883fdadfa90ac7e7d1c68fa7ef19749f263c3a1811"))));
    }
}
