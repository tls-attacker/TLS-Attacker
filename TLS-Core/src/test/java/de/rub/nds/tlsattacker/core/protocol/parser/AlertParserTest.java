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
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class AlertParserTest extends AbstractProtocolMessageParserTest<AlertMessage, AlertParser> {

    public AlertParserTest() {
        super(
                AlertMessage.class,
                AlertParser::new,
                List.of(
                        Named.of("AlertMessage::getLevel", AlertMessage::getLevel),
                        Named.of("AlertMessage::getDescription", AlertMessage::getDescription)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("0102"),
                        List.of((byte) 0x01, (byte) 0x02)),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("0403"),
                        List.of((byte) 0x04, (byte) 0x03)));
    }
}
