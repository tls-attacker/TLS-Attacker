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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class ExtendedMasterSecretExtensionParserTest
    extends AbstractExtensionParserTest<ExtendedMasterSecretExtensionMessage, ExtendedMasterSecretExtensionParser> {

    public ExtendedMasterSecretExtensionParserTest() {
        super(ExtendedMasterSecretExtensionParser::new);
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("00170000"), List.of(),
            ExtensionType.EXTENDED_MASTER_SECRET, 0, List.of()));
    }
}
