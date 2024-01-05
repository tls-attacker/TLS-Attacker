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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class HelloVerifyRequestParserTest
        extends AbstractHandshakeMessageParserTest<
                HelloVerifyRequestMessage, HelloVerifyRequestParser> {

    public HelloVerifyRequestParserTest() {
        super(
                HelloVerifyRequestMessage.class,
                HelloVerifyRequestParser::new,
                List.of(
                        Named.of(
                                "HelloVerifyRequestMessage::getProtocolVersion",
                                HelloVerifyRequestMessage::getProtocolVersion),
                        Named.of(
                                "HelloVerifyRequestMessage::getCookieLength",
                                HelloVerifyRequestMessage::getCookieLength),
                        Named.of(
                                "HelloVerifyRequestMessage::getCookie",
                                HelloVerifyRequestMessage::getCookie)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.DTLS10,
                        ArrayConverter.hexStringToByteArray(
                                "03000017feff1415520276466763250a851c5b9eaeb44676ff3381"),
                        List.of(
                                HandshakeMessageType.HELLO_VERIFY_REQUEST.getValue(),
                                23,
                                ProtocolVersion.DTLS10.getValue(),
                                (byte) 20,
                                ArrayConverter.hexStringToByteArray(
                                        "15520276466763250a851c5b9eaeb44676ff3381"))));
    }
}
