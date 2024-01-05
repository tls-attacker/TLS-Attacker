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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ClientAuthzExtensionParserTest
        extends AbstractExtensionParserTest<
                ClientAuthzExtensionMessage, ClientAuthzExtensionParser> {

    public ClientAuthzExtensionParserTest() {
        super(
                ClientAuthzExtensionMessage.class,
                ClientAuthzExtensionParser::new,
                List.of(
                        Named.of(
                                "ClientAuthzExtensionMessage::getAuthzFormatListLength",
                                ClientAuthzExtensionMessage::getAuthzFormatListLength),
                        Named.of(
                                "ClientAuthzExtensionMessage::getAuthzFormatList",
                                ClientAuthzExtensionMessage::getAuthzFormatList)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("000700050400010203"),
                        List.of(),
                        ExtensionType.CLIENT_AUTHZ,
                        5,
                        List.of(4, ArrayConverter.hexStringToByteArray("00010203"))));
    }
}
