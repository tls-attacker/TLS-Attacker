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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PaddingExtensionParserTest
        extends AbstractExtensionParserTest<PaddingExtensionMessage, PaddingExtensionParser> {

    public PaddingExtensionParserTest() {
        super(
                PaddingExtensionMessage.class,
                PaddingExtensionParser::new,
                List.of(
                        Named.of(
                                "PaddingExtensionMessage::getPaddingBytes",
                                PaddingExtensionMessage::getPaddingBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("00150006000000000000"),
                        List.of(),
                        ExtensionType.PADDING,
                        6,
                        List.of(new byte[] {0, 0, 0, 0, 0, 0})));
    }
}
