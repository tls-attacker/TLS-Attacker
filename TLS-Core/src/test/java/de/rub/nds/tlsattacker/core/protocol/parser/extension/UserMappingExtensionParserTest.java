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
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class UserMappingExtensionParserTest
        extends AbstractExtensionParserTest<
                UserMappingExtensionMessage, UserMappingExtensionParser> {

    public UserMappingExtensionParserTest() {
        super(
                UserMappingExtensionMessage.class,
                UserMappingExtensionParser::new,
                List.of(
                        Named.of(
                                "UserMappingExtensionMessage::getUserMappingType",
                                UserMappingExtensionMessage::getUserMappingType)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("0006000140"),
                        List.of(),
                        ExtensionType.USER_MAPPING,
                        1,
                        List.of(UserMappingExtensionHintType.UPN_DOMAIN_HINT.getValue())));
    }
}
