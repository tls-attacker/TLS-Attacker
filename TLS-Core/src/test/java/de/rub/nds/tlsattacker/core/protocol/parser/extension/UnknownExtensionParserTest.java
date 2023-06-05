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
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class UnknownExtensionParserTest
        extends AbstractExtensionParserTest<UnknownExtensionMessage, UnknownExtensionParser> {

    public UnknownExtensionParserTest() {
        super(
                UnknownExtensionMessage.class,
                UnknownExtensionParser::new,
                List.of(
                        Named.of(
                                "UnknownExtensionMessage::getExtensionData",
                                UnknownExtensionMessage::getExtensionData)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("00230000"),
                        List.of(),
                        ArrayConverter.hexStringToByteArray("0023"),
                        0,
                        Collections.singletonList(new byte[0])),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("000f000101"),
                        List.of(),
                        ArrayConverter.hexStringToByteArray("000f"),
                        1,
                        List.of(ArrayConverter.hexStringToByteArray("01"))),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("00000000"),
                        List.of(),
                        ArrayConverter.hexStringToByteArray("0000"),
                        0,
                        Collections.singletonList(new byte[0])),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("0000FFFF"),
                        List.of(),
                        ArrayConverter.hexStringToByteArray("0000"),
                        0xFFFF,
                        Collections.singletonList(new byte[0])));
    }
}
