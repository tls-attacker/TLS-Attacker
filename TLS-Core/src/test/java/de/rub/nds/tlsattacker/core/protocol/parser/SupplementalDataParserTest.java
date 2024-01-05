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
import de.rub.nds.tlsattacker.core.protocol.message.SupplementalDataMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class SupplementalDataParserTest
        extends AbstractHandshakeMessageParserTest<
                SupplementalDataMessage, SupplementalDataParser> {

    public SupplementalDataParserTest() {
        super(
                SupplementalDataMessage.class,
                SupplementalDataParser::new,
                List.of(
                        Named.of(
                                "SupplementalDataMessage::getSupplementalDataLength",
                                SupplementalDataMessage::getSupplementalDataLength),
                        Named.of(
                                "SupplementalDataMessage::getSupplementalDataBytes",
                                SupplementalDataMessage::getSupplementalDataBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray(
                                "1700001100000e4002000a0008010005aaaaaaaaaa"),
                        List.of(
                                HandshakeMessageType.SUPPLEMENTAL_DATA.getValue(),
                                17,
                                14,
                                ArrayConverter.hexStringToByteArray(
                                        "4002000a0008010005aaaaaaaaaa"))),
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray(
                                "1700001F00001c4002000a0008010005aaaaaaaaaa4002000a0008010005aaaaaaaaaa"),
                        List.of(
                                HandshakeMessageType.SUPPLEMENTAL_DATA.getValue(),
                                31,
                                28,
                                ArrayConverter.hexStringToByteArray(
                                        "4002000a0008010005aaaaaaaaaa4002000a0008010005aaaaaaaaaa"))));
    }
}
