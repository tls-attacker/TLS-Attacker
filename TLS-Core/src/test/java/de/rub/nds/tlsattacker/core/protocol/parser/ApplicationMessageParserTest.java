/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ApplicationMessageParserTest
        extends AbstractProtocolMessageParserTest<ApplicationMessage, ApplicationMessageParser> {

    public ApplicationMessageParserTest() {
        super(
                ApplicationMessage.class,
                ApplicationMessageParser::new,
                List.of(Named.of("ApplicationMessage::getData", ApplicationMessage::getData)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("00010203040506"),
                        List.of(ArrayConverter.hexStringToByteArray("00010203040506"))));
    }
}
