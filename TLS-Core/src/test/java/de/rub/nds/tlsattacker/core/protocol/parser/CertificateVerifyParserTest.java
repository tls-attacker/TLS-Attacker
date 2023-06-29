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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateVerifyParserTest
        extends AbstractHandshakeMessageParserTest<
                CertificateVerifyMessage, CertificateVerifyParser> {

    public CertificateVerifyParserTest() {
        super(
                CertificateVerifyMessage.class,
                CertificateVerifyParser::new,
                List.of(
                        Named.of(
                                "CertificateVerifyMessage::getSignatureHashAlgorithm",
                                CertificateVerifyMessage::getSignatureHashAlgorithm),
                        Named.of(
                                "CertificateVerifyMessage::getSignatureLength",
                                CertificateVerifyMessage::getSignatureLength),
                        Named.of(
                                "CertificateVerifyMessage::getSignature",
                                CertificateVerifyMessage::getSignature)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "0f000104060101003999111fdc06f04c1fffb3ba62f36784789b1f12b49f72f829139e845dfca51379aeb70e707cd70a38ed58c8fd8d033c62e8fc3175012a6ada4728b0aaa243ce57822ada6fa33b05e5220fb2719b7039831d060e455ccb9b017201c0b8e774455af62439373cbe43beee0653d06d0ed333f68aaa3efca34e890491a0e36aa12903d56889cae1b4b07bcfe98399375d9803105ceba1a07ef02cf1bea1e8395ea981b113ef5dd74870e8b7447cf36767ca7c2d3e95d5bd114ff0425af2b0616ef1e3c1a3e8e1f6df789a5c30ac0eb10f3364cdf95125a3dc874786b8705d2d93fa7a4c764ea943d43e9da54bc6ab088de869389a565c86f46a01e49bbebfa3b1fd"),
                        List.of(
                                HandshakeMessageType.CERTIFICATE_VERIFY.getValue(),
                                260,
                                new byte[] {0x06, 0x01},
                                256,
                                ArrayConverter.hexStringToByteArray(
                                        "3999111fdc06f04c1fffb3ba62f36784789b1f12b49f72f829139e845dfca51379aeb70e707cd70a38ed58c8fd8d033c62e8fc3175012a6ada4728b0aaa243ce57822ada6fa33b05e5220fb2719b7039831d060e455ccb9b017201c0b8e774455af62439373cbe43beee0653d06d0ed333f68aaa3efca34e890491a0e36aa12903d56889cae1b4b07bcfe98399375d9803105ceba1a07ef02cf1bea1e8395ea981b113ef5dd74870e8b7447cf36767ca7c2d3e95d5bd114ff0425af2b0616ef1e3c1a3e8e1f6df789a5c30ac0eb10f3364cdf95125a3dc874786b8705d2d93fa7a4c764ea943d43e9da54bc6ab088de869389a565c86f46a01e49bbebfa3b1fd"))));
    }
}
