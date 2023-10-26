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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ServerNameIndicationExtensionParserTest
        extends AbstractExtensionParserTest<
                ServerNameIndicationExtensionMessage, ServerNameIndicationExtensionParser> {

    public ServerNameIndicationExtensionParserTest() {
        super(
                ServerNameIndicationExtensionMessage.class,
                ServerNameIndicationExtensionParser::new,
                List.of(
                        Named.of(
                                "ServerNameIndicationExtensionMessage::getServerNameListLength",
                                ServerNameIndicationExtensionMessage::getServerNameListLength),
                        Named.of(
                                "ServerNameIndicationExtensionMessage::getServerNameListBytes",
                                ServerNameIndicationExtensionMessage::getServerNameListBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                // case 1: completion.amazon.com
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "0000001a0018000015636f6d706c6574696f6e2e616d617a6f6e2e636f6d"),
                        List.of(),
                        ExtensionType.SERVER_NAME_INDICATION,
                        26,
                        List.of(
                                24,
                                ArrayConverter.hexStringToByteArray(
                                        "000015636f6d706c6574696f6e2e616d617a6f6e2e636f6d"))),
                // case 2: guzzoni.apple.com
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "00000016001400001167757a7a6f6e692e6170706c652e636f6d"),
                        List.of(),
                        ExtensionType.SERVER_NAME_INDICATION,
                        22,
                        List.of(
                                20,
                                ArrayConverter.hexStringToByteArray(
                                        "00001167757a7a6f6e692e6170706c652e636f6d"))),
                // case 3: www.google.com, test.dummy.com
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "00000024002200000e7777772e676f6f676c652e636f6d00000e746573742e64756d6d792e636f6d"),
                        List.of(),
                        ExtensionType.SERVER_NAME_INDICATION,
                        36,
                        List.of(
                                34,
                                ArrayConverter.hexStringToByteArray(
                                        "00000e7777772e676f6f676c652e636f6d00000e746573742e64756d6d792e636f6d"))));
    }
}
