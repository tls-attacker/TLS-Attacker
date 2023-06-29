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
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class PWDClientKeyExchangeParserTest
        extends AbstractHandshakeMessageParserTest<
                PWDClientKeyExchangeMessage, PWDClientKeyExchangeParser> {

    public PWDClientKeyExchangeParserTest() {
        super(
                PWDClientKeyExchangeMessage.class,
                PWDClientKeyExchangeParser::new,
                List.of(
                        Named.of(
                                "PWDClientKeyExchangeMessage::getElementLength",
                                PWDClientKeyExchangeMessage::getElementLength),
                        Named.of(
                                "PWDClientKeyExchangeMessage::getElement",
                                PWDClientKeyExchangeMessage::getElement),
                        Named.of(
                                "PWDClientKeyExchangeMessage::getScalarLength",
                                PWDClientKeyExchangeMessage::getScalarLength),
                        Named.of(
                                "PWDClientKeyExchangeMessage::getScalar",
                                PWDClientKeyExchangeMessage::getScalar),
                        Named.of(
                                "ClientKeyExchangeMessage::getPublicKeyLength",
                                ClientKeyExchangeMessage::getPublicKeyLength),
                        Named.of(
                                "ClientKeyExchangeMessage::getPublicKey",
                                ClientKeyExchangeMessage::getPublicKey)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "100000634104a0c69b450b85aee39f646b6e64d3c108395f4ba1192dbfebf0dec5b189131f595dd4bacdbdd6838d9219fd542991b2c0b0e4c446bfe58f3c0339f756e89efda020669244aa67cb00ea72c09b84a9db5bb824fc3982428fcd406963ae080e677a48"),
                        Arrays.asList(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                                99,
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "04a0c69b450b85aee39f646b6e64d3c108395f4ba1192dbfebf0dec5b189131f595dd4bacdbdd6838d9219fd542991b2c0b0e4c446bfe58f3c0339f756e89efda0"),
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "669244aa67cb00ea72c09b84a9db5bb824fc3982428fcd406963ae080e677a48"),
                                null,
                                null)));
    }
}
