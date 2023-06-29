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
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class GreaseExtensionParserTest
        extends AbstractExtensionParserTest<GreaseExtensionMessage, GreaseExtensionParser> {

    public GreaseExtensionParserTest() {
        super(
                GreaseExtensionMessage.class,
                GreaseExtensionParser::new,
                List.of(
                        Named.of(
                                "GreaseExtensionMessage::getData",
                                GreaseExtensionMessage::getData)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("1a1a000a0102030405060708090a"),
                        List.of(),
                        ExtensionType.GREASE_01,
                        10,
                        List.of(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10})));
    }
}
