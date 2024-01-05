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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class SupportedVersionsExtensionParserTest
        extends AbstractExtensionParserTest<
                SupportedVersionsExtensionMessage, SupportedVersionsExtensionParser> {

    public SupportedVersionsExtensionParserTest() {
        super(
                SupportedVersionsExtensionMessage.class,
                SupportedVersionsExtensionParser::new,
                List.of(
                        Named.of(
                                "SupportedVersionsExtensionMessage::getSupportedVersionsLength",
                                SupportedVersionsExtensionMessage::getSupportedVersionsLength),
                        Named.of(
                                "SupportedVersionsExtensionMessage::getSupportedVersions",
                                SupportedVersionsExtensionMessage::getSupportedVersions)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("002B000D0C000203000301030203037F14"),
                        List.of(),
                        ExtensionType.SUPPORTED_VERSIONS,
                        13,
                        List.of(
                                12,
                                ArrayConverter.hexStringToByteArray("000203000301030203037F14"))));
    }
}
