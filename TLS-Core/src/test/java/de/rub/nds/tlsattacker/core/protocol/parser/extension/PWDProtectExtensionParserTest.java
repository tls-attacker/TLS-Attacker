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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PWDProtectExtensionParserTest
        extends AbstractExtensionParserTest<PWDProtectExtensionMessage, PWDProtectExtensionParser> {

    public PWDProtectExtensionParserTest() {
        super(
                PWDProtectExtensionMessage.class,
                PWDProtectExtensionParser::new,
                List.of(
                        Named.of(
                                "PWDProtectExtensionMessage::getUsernameLength",
                                PWDProtectExtensionMessage::getUsernameLength),
                        Named.of(
                                "PWDProtectExtensionMessage::getUsername",
                                PWDProtectExtensionMessage::getUsername)));
    }

    /**
     * Generate test data for the parser and serializer
     *
     * <p>Note that the "username" is not actually an encrypted byte string in this test. The parser
     * and serializer don't really care about that. This is just to test if the field is extracted
     * correctly. The actual encryption/decryption is done by the handler/preparator.
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("001d00050466726564"),
                        List.of(),
                        ExtensionType.PWD_PROTECT,
                        5,
                        List.of(4, ArrayConverter.hexStringToByteArray("66726564"))));
    }
}
