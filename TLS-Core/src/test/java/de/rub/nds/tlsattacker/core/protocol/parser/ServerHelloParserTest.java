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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class ServerHelloParserTest
        extends AbstractHandshakeMessageParserTest<ServerHelloMessage, ServerHelloParser> {

    public ServerHelloParserTest() {
        super(
                ServerHelloMessage.class,
                ServerHelloParser::new,
                List.of(
                        Named.of(
                                "HelloMessage::getProtocolVersion",
                                HelloMessage::getProtocolVersion),
                        Named.of("HelloMessage::getUnixTime", HelloMessage::getUnixTime),
                        Named.of("HelloMessage::getRandom", HelloMessage::getRandom),
                        Named.of(
                                "HelloMessage::getSessionIdLength",
                                HelloMessage::getSessionIdLength),
                        Named.of("HelloMessage::getSessionId", HelloMessage::getSessionId),
                        Named.of(
                                "ServerHelloMessage::getSelectedCipherSuite",
                                ServerHelloMessage::getSelectedCipherSuite),
                        Named.of(
                                "ServerHelloMessage::getSelectedCompressionMethod",
                                ServerHelloMessage::getSelectedCompressionMethod),
                        Named.of(
                                "HelloMessage::getExtensionsLength",
                                HelloMessage::getExtensionsLength),
                        Named.of(
                                "HelloMessage::getExtensionBytes", HelloMessage::getExtensionBytes),
                        Named.of(
                                "HelloMessage::getExtensions::size",
                                (msg) -> msg.getExtensions().size())));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "020000480303378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01200919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10002f000000"),
                        List.of(
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                72,
                                ProtocolVersion.TLS12.getValue(),
                                ArrayConverter.hexStringToByteArray("378f93cb"),
                                ArrayConverter.hexStringToByteArray(
                                        "378f93cbcafda4c9ba43dafb49ab847ba1ae86a29d2679e7b9aac8e25c207e01"),
                                32,
                                ArrayConverter.hexStringToByteArray(
                                        "0919fe8a189912807ee0621a45f4e6440a297f13574d2229fdbc96427b0e2d10"),
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue(),
                                CompressionMethod.NULL.getValue(),
                                0,
                                new byte[0],
                                0)),
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray(
                                "020000360302697b9fc9eeba3fc98a15c6c08f3b8818fb1413b95f57679673fe55721872117b00003500000eff0100010000230000000f000101"),
                        List.of(
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                54,
                                ProtocolVersion.TLS11.getValue(),
                                ArrayConverter.hexStringToByteArray("697b9fc9"),
                                ArrayConverter.hexStringToByteArray(
                                        "697b9fc9eeba3fc98a15c6c08f3b8818fb1413b95f57679673fe55721872117b"),
                                0,
                                new byte[0],
                                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA.getByteValue(),
                                CompressionMethod.NULL.getValue(),
                                14,
                                ArrayConverter.hexStringToByteArray("ff0100010000230000000f000101"),
                                3)),
                Arguments.of(
                        ProtocolVersion.TLS10,
                        ArrayConverter.hexStringToByteArray(
                                "0200003603013a40a6187edfd84f419fb68b7ab2aaa83ffb0e88a61c7d741be0467faeaa56f100003500000eff0100010000230000000f000101"),
                        List.of(
                                HandshakeMessageType.SERVER_HELLO.getValue(),
                                54,
                                ProtocolVersion.TLS10.getValue(),
                                ArrayConverter.hexStringToByteArray("3a40a618"),
                                ArrayConverter.hexStringToByteArray(
                                        "3a40a6187edfd84f419fb68b7ab2aaa83ffb0e88a61c7d741be0467faeaa56f1"),
                                0,
                                new byte[0],
                                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA.getByteValue(),
                                CompressionMethod.NULL.getValue(),
                                14,
                                ArrayConverter.hexStringToByteArray("ff0100010000230000000f000101"),
                                3)));
    }
}
