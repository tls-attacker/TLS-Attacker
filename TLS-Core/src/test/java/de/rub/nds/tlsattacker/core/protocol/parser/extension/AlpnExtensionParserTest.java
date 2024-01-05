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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class AlpnExtensionParserTest
        extends AbstractExtensionParserTest<AlpnExtensionMessage, AlpnExtensionParser> {

    public AlpnExtensionParserTest() {
        super(
                AlpnExtensionMessage.class,
                AlpnExtensionParser::new,
                List.of(
                        Named.of(
                                "AlpnExtensionMessage::getProposedAlpnProtocolsLength",
                                AlpnExtensionMessage::getProposedAlpnProtocolsLength),
                        Named.of(
                                "AlpnExtensionMessage::getProposedAlpnProtocols",
                                AlpnExtensionMessage::getProposedAlpnProtocols)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("0010000e000c02683208687474702f312e31"),
                        List.of(),
                        ExtensionType.ALPN,
                        14,
                        List.of(
                                12,
                                ArrayConverter.hexStringToByteArray("02683208687474702f312e31"))));
    }
}
