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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PasswordSaltExtensionParserTest
        extends AbstractExtensionParserTest<
                PasswordSaltExtensionMessage, PasswordSaltExtensionParser> {

    public PasswordSaltExtensionParserTest() {
        super(
                PasswordSaltExtensionMessage.class,
                PasswordSaltExtensionParser::new,
                List.of(
                        Named.of(
                                "PasswordSaltExtensionMessage::getSaltLength",
                                PasswordSaltExtensionMessage::getSaltLength),
                        Named.of(
                                "PasswordSaltExtensionMessage::getSalt",
                                PasswordSaltExtensionMessage::getSalt)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "001f00120010843711c21d47ce6e6383cdda37e47da3"),
                        List.of(),
                        ExtensionType.PASSWORD_SALT,
                        18,
                        List.of(
                                16,
                                ArrayConverter.hexStringToByteArray(
                                        "843711c21d47ce6e6383cdda37e47da3"))));
    }
}
