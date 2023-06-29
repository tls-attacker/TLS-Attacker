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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class SRPExtensionParserTest
        extends AbstractExtensionParserTest<SRPExtensionMessage, SRPExtensionParser> {

    public SRPExtensionParserTest() {
        super(
                SRPExtensionMessage.class,
                SRPExtensionParser::new,
                List.of(
                        Named.of(
                                "SRPExtensionMessage::getSrpIdentifierLength",
                                SRPExtensionMessage::getSrpIdentifierLength),
                        Named.of(
                                "SRPExtensionMessage::getSrpIdentifier",
                                SRPExtensionMessage::getSrpIdentifier)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        new byte[] {0x00, 0x0C, 0x00, 0x05, 0x04, 0x01, 0x02, 0x03, 0x04},
                        List.of(),
                        ExtensionType.SRP,
                        5,
                        List.of(4, ArrayConverter.hexStringToByteArray("01020304"))));
    }
}
