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
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class RenegotiationInfoExtensionParserTest
        extends AbstractExtensionParserTest<
                RenegotiationInfoExtensionMessage, RenegotiationInfoExtensionParser> {

    public RenegotiationInfoExtensionParserTest() {
        super(
                RenegotiationInfoExtensionMessage.class,
                RenegotiationInfoExtensionParser::new,
                List.of(
                        Named.of(
                                "RenegotiationInfoExtensionMessage::getRenegotiationInfoLength",
                                RenegotiationInfoExtensionMessage::getRenegotiationInfoLength),
                        Named.of(
                                "RenegotiationInfoExtensionMessage::getRenegotiationInfo",
                                RenegotiationInfoExtensionMessage::getRenegotiationInfo)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("ff01000100"),
                        List.of(),
                        ExtensionType.RENEGOTIATION_INFO,
                        1,
                        List.of(0, new byte[0])));
    }
}
