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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class HeartbeatMessageParserTest
        extends AbstractProtocolMessageParserTest<HeartbeatMessage, HeartbeatMessageParser> {

    public HeartbeatMessageParserTest() {
        super(
                HeartbeatMessage.class,
                HeartbeatMessageParser::new,
                List.of(
                        Named.of(
                                "HeartbeatMessage::getHeartbeatMessageType",
                                HeartbeatMessage::getHeartbeatMessageType),
                        Named.of(
                                "HeartbeatMessage::getPayloadLength",
                                HeartbeatMessage::getPayloadLength),
                        Named.of("HeartbeatMessage::getPayload", HeartbeatMessage::getPayload),
                        Named.of("HeartbeatMessage::getPadding", HeartbeatMessage::getPadding)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "010012000075a6d1d422693ea31584902266171b14ee376d595f5c65aeba8d04b0378faeda"),
                        List.of(
                                (byte) 0x01,
                                18,
                                ArrayConverter.hexStringToByteArray(
                                        "000075a6d1d422693ea31584902266171b14"),
                                ArrayConverter.hexStringToByteArray(
                                        "ee376d595f5c65aeba8d04b0378faeda"))),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "020012000075a6d1d422693ea31584902266171b1429ee15bbaa07f19c012dc29e2449e1e1"),
                        List.of(
                                (byte) 0x02,
                                18,
                                ArrayConverter.hexStringToByteArray(
                                        "000075a6d1d422693ea31584902266171b14"),
                                ArrayConverter.hexStringToByteArray(
                                        "29ee15bbaa07f19c012dc29e2449e1e1"))));
    }
}
