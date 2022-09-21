/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class ExtendedRandomExtensionParserTest
    extends AbstractExtensionParserTest<ExtendedRandomExtensionMessage, ExtendedRandomExtensionParser> {

    public ExtendedRandomExtensionParserTest() {
        super(ExtendedRandomExtensionParser::new,
            List.of(
                Named.of("ExtendedRandomExtensionMessage::getExtendedRandomLength",
                    ExtendedRandomExtensionMessage::getExtendedRandomLength),
                Named.of("ExtendedRandomExtensionMessage::getExtendedRandom",
                    ExtendedRandomExtensionMessage::getExtendedRandom)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("002800030001AB"), List.of(),
            ExtensionType.EXTENDED_RANDOM, 3, List.of(1, ArrayConverter.hexStringToByteArray("AB"))));
    }
}
