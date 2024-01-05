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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SrtpExtensionMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class SrtpExtensionParserTest
        extends AbstractExtensionParserTest<SrtpExtensionMessage, SrtpExtensionParser> {

    public SrtpExtensionParserTest() {
        super(
                SrtpExtensionMessage.class,
                SrtpExtensionParser::new,
                List.of(
                        Named.of(
                                "SrtpExtensionMessage::getSrtpProtectionProfilesLength",
                                SrtpExtensionMessage::getSrtpProtectionProfilesLength),
                        Named.of(
                                "SrtpExtensionMessage::getSrtpProtectionProfiles",
                                SrtpExtensionMessage::getSrtpProtectionProfiles),
                        Named.of(
                                "SrtpExtensionMessage::getSrtpMkiLength",
                                SrtpExtensionMessage::getSrtpMkiLength),
                        Named.of(
                                "SrtpExtensionMessage::getSrtpMki",
                                SrtpExtensionMessage::getSrtpMki)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("000e0009000400010006020102"),
                        List.of(),
                        ExtensionType.USE_SRTP,
                        9,
                        List.of(
                                4,
                                ArrayConverter.hexStringToByteArray("00010006"),
                                2,
                                new byte[] {0x01, 0x02})),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("000e000900040001000600"),
                        List.of(),
                        ExtensionType.USE_SRTP,
                        9,
                        List.of(
                                4,
                                ArrayConverter.hexStringToByteArray("00010006"),
                                0,
                                new byte[0])));
    }
}
