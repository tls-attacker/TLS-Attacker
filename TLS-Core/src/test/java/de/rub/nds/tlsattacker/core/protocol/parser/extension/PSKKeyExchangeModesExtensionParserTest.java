/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PSKKeyExchangeModesExtensionParserTest
        extends AbstractExtensionParserTest<
                PSKKeyExchangeModesExtensionMessage, PSKKeyExchangeModesExtensionParser> {

    public PSKKeyExchangeModesExtensionParserTest() {
        super(
                PSKKeyExchangeModesExtensionMessage.class,
                PSKKeyExchangeModesExtensionParser::new,
                List.of(
                        Named.of(
                                "PSKKeyExchangeModesExtensionMessage::getKeyExchangeModesListLength",
                                PSKKeyExchangeModesExtensionMessage::getKeyExchangeModesListLength),
                        Named.of(
                                "PSKKeyExchangeModesExtensionMessage::getKeyExchangeModesListBytes",
                                PSKKeyExchangeModesExtensionMessage
                                        ::getKeyExchangeModesListBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("002D0003020001"),
                        List.of(),
                        ExtensionType.PSK_KEY_EXCHANGE_MODES,
                        3,
                        List.of(2, new byte[] {0x00, 0x01})),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("002D000100"),
                        List.of(),
                        ExtensionType.PSK_KEY_EXCHANGE_MODES,
                        1,
                        List.of(0, new byte[0])));
    }
}
