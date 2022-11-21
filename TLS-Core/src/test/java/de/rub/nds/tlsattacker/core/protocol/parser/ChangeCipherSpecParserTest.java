/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class ChangeCipherSpecParserTest
    extends AbstractTlsMessageParserTest<ChangeCipherSpecMessage, ChangeCipherSpecParser> {

    public ChangeCipherSpecParserTest() {
        super(ChangeCipherSpecParser::new, List
            .of(Named.of("ChangeCipherSpecMessage::getCcsProtocolType", ChangeCipherSpecMessage::getCcsProtocolType)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ProtocolVersion.TLS12, new byte[] { 0x01 }, List.of(new byte[] { 0x01 })),
            Arguments.of(ProtocolVersion.TLS12, new byte[] { 0x05 }, List.of(new byte[] { 0x05 })),
            Arguments.of(ProtocolVersion.TLS10, new byte[] { 0x01 }, List.of(new byte[] { 0x01 })),
            Arguments.of(ProtocolVersion.TLS11, new byte[] { 0x01 }, List.of(new byte[] { 0x01 })));
    }
}
