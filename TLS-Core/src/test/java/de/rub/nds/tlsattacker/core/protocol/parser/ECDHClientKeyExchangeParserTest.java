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
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ECDHClientKeyExchangeParserTest
        extends AbstractHandshakeMessageParserTest<
                ECDHClientKeyExchangeMessage,
                ECDHClientKeyExchangeParser<ECDHClientKeyExchangeMessage>> {

    public ECDHClientKeyExchangeParserTest() {
        super(
                ECDHClientKeyExchangeMessage.class,
                ECDHClientKeyExchangeParser::new,
                List.of(
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
                                "100000424104ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"),
                        List.of(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                                66,
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "04ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"))),
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray(
                                "100000424104b4b5b76d94709ec280af4f806b13e20e227e60d98a65204935e804076c829cd33ca5b7ff016584aeccc42a0b6db366cbb64a20af8c03ba6311a59552b3fad23e"),
                        List.of(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                                66,
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "04b4b5b76d94709ec280af4f806b13e20e227e60d98a65204935e804076c829cd33ca5b7ff016584aeccc42a0b6db366cbb64a20af8c03ba6311a59552b3fad23e"))),
                Arguments.of(
                        ProtocolVersion.TLS10,
                        ArrayConverter.hexStringToByteArray(
                                "1000004241043775fe5c151587cc5b28958ea43b62ed642e02df9d6d58a17ac91756cbc8638ff5d22490ffc3e3abc144a5ecc5b54e84a576e7cd0df6863b35a55464e5038777"),
                        List.of(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE.getValue(),
                                66,
                                65,
                                ArrayConverter.hexStringToByteArray(
                                        "043775fe5c151587cc5b28958ea43b62ed642e02df9d6d58a17ac91756cbc8638ff5d22490ffc3e3abc144a5ecc5b54e84a576e7cd0df6863b35a55464e5038777"))));
    }
}
