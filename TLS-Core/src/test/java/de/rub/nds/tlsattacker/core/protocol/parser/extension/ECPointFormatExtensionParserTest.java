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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ECPointFormatExtensionParserTest
        extends AbstractExtensionParserTest<
                ECPointFormatExtensionMessage, ECPointFormatExtensionParser> {

    public ECPointFormatExtensionParserTest() {
        super(
                ECPointFormatExtensionMessage.class,
                ECPointFormatExtensionParser::new,
                List.of(
                        Named.of(
                                "ECPointFormatExtensionMessage::getPointFormatsLength",
                                ECPointFormatExtensionMessage::getPointFormatsLength),
                        Named.of(
                                "ECPointFormatExtensionMessage::getPointFormats",
                                ECPointFormatExtensionMessage::getPointFormats)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("000b000403000102"),
                        List.of(),
                        ExtensionType.EC_POINT_FORMATS,
                        4,
                        List.of(3, new byte[] {0, 1, 2})));
    }
}
