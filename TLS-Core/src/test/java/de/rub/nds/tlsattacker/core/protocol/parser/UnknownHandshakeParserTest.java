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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class UnknownHandshakeParserTest
        extends AbstractHandshakeMessageParserTest<
                UnknownHandshakeMessage, UnknownHandshakeParser> {

    public UnknownHandshakeParserTest() {
        super(
                UnknownHandshakeMessage.class,
                UnknownHandshakeParser::new,
                List.of(
                        Named.of(
                                "UnknownHandshakeMessage::getData",
                                UnknownHandshakeMessage::getData)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "040000a60000012c00a02f8dbba0bca89176bf21d4e640f729dcbded6af280556e9b4b18a6c8218f01976780232a6765e278ecc516fb19bb9ec6e3913ed27a6123eefa188212c4e5d611c85c55fb32358c0896c00781392039aae9df79ebad27860e9d5016df72bd6de898502e6221481e0f375c949e44adb6fd7fcf33e9d431a223dcf7bb72fc585ae1d8df34178bbdc5e553657dd615dc38c59b49970129c937e961f1a87a60af1e26"),
                        List.of(
                                (byte) 0x04,
                                166,
                                ArrayConverter.hexStringToByteArray(
                                        "0000012c00a02f8dbba0bca89176bf21d4e640f729dcbded6af280556e9b4b18a6c8218f01976780232a6765e278ecc516fb19bb9ec6e3913ed27a6123eefa188212c4e5d611c85c55fb32358c0896c00781392039aae9df79ebad27860e9d5016df72bd6de898502e6221481e0f375c949e44adb6fd7fcf33e9d431a223dcf7bb72fc585ae1d8df34178bbdc5e553657dd615dc38c59b49970129c937e961f1a87a60af1e26"))));
    }
}
