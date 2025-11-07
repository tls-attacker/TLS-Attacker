/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.DebugExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class DebugExtensionParserTest
        extends AbstractExtensionParserTest<DebugExtensionMessage, DebugExtensionParser> {

    public DebugExtensionParserTest() {
        super(
                DebugExtensionMessage.class,
                DebugExtensionParser::new,
                List.of(
                        Named.of(
                                "DebugExtensionMessage::getDebugContent",
                                DebugExtensionMessage::getDebugContent)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        DataConverter.hexStringToByteArray(
                                "fbfb001a544c532d41747461636b657220446562756720436f6e74656e74"),
                        List.of(),
                        ExtensionType.DEBUG,
                        26,
                        List.of("TLS-Attacker Debug Content")));
    }
}
