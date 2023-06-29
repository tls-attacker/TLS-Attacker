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
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class TruncatedHmacExtensionParserTest
        extends AbstractExtensionParserTest<
                TruncatedHmacExtensionMessage, TruncatedHmacExtensionParser> {

    public TruncatedHmacExtensionParserTest() {
        super(TruncatedHmacExtensionMessage.class, TruncatedHmacExtensionParser::new);
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("00040000"),
                        List.of(),
                        ExtensionType.TRUNCATED_HMAC,
                        0,
                        List.of()));
    }
}
