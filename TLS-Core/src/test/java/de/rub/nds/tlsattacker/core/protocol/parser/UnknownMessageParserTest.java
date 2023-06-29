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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class UnknownMessageParserTest
        extends AbstractProtocolMessageParserTest<UnknownMessage, UnknownMessageParser> {

    public UnknownMessageParserTest() {
        super(UnknownMessage.class, (stream, tlsContext) -> new UnknownMessageParser(stream));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray("00010203"),
                        List.of(
                                // Only used during serializer test
                                ArrayConverter.hexStringToByteArray("00010203"))));
    }
}
