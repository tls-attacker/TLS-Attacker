/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateVerifyMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("0f000104060101003999111fdc06f04c1fffb3ba62f36784789b1f12b49f72f829139e845dfca51379aeb70e707cd70a38ed58c8fd8d033c62e8fc3175012a6ada4728b0aaa243ce57822ada6fa33b05e5220fb2719b7039831d060e455ccb9b017201c0b8e774455af62439373cbe43beee0653d06d0ed333f68aaa3efca34e890491a0e36aa12903d56889cae1b4b07bcfe98399375d9803105ceba1a07ef02cf1bea1e8395ea981b113ef5dd74870e8b7447cf36767ca7c2d3e95d5bd114ff0425af2b0616ef1e3c1a3e8e1f6df789a5c30ac0eb10f3364cdf95125a3dc874786b8705d2d93fa7a4c764ea943d43e9da54bc6ab088de869389a565c86f46a01e49bbebfa3b1fd"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("0f000104060101003999111fdc06f04c1fffb3ba62f36784789b1f12b49f72f829139e845dfca51379aeb70e707cd70a38ed58c8fd8d033c62e8fc3175012a6ada4728b0aaa243ce57822ada6fa33b05e5220fb2719b7039831d060e455ccb9b017201c0b8e774455af62439373cbe43beee0653d06d0ed333f68aaa3efca34e890491a0e36aa12903d56889cae1b4b07bcfe98399375d9803105ceba1a07ef02cf1bea1e8395ea981b113ef5dd74870e8b7447cf36767ca7c2d3e95d5bd114ff0425af2b0616ef1e3c1a3e8e1f6df789a5c30ac0eb10f3364cdf95125a3dc874786b8705d2d93fa7a4c764ea943d43e9da54bc6ab088de869389a565c86f46a01e49bbebfa3b1fd"),
                        HandshakeMessageType.CERTIFICATE_VERIFY,
                        260,
                        new byte[] { 0x06, 0x01 },
                        256,
                        ArrayConverter
                                .hexStringToByteArray("3999111fdc06f04c1fffb3ba62f36784789b1f12b49f72f829139e845dfca51379aeb70e707cd70a38ed58c8fd8d033c62e8fc3175012a6ada4728b0aaa243ce57822ada6fa33b05e5220fb2719b7039831d060e455ccb9b017201c0b8e774455af62439373cbe43beee0653d06d0ed333f68aaa3efca34e890491a0e36aa12903d56889cae1b4b07bcfe98399375d9803105ceba1a07ef02cf1bea1e8395ea981b113ef5dd74870e8b7447cf36767ca7c2d3e95d5bd114ff0425af2b0616ef1e3c1a3e8e1f6df789a5c30ac0eb10f3364cdf95125a3dc874786b8705d2d93fa7a4c764ea943d43e9da54bc6ab088de869389a565c86f46a01e49bbebfa3b1fd") }, });
    }

    private byte[] message;

    private HandshakeMessageType type;
    private int length;

    private byte[] sigHashAlgo;
    private int signatureLength;
    private byte[] signature;

    public CertificateVerifyMessageParserTest(byte[] message, int start, byte[] expectedPart,
            HandshakeMessageType type, int length, byte[] sigHashAlgo, int signatureLength, byte[] signature) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.sigHashAlgo = sigHashAlgo;
        this.signatureLength = signatureLength;
        this.signature = signature;
    }

    /**
     * Test of parse method, of class CertificateVerifyParser.
     */
    @Test
    public void testParse() {
        CertificateVerifyParser parser = new CertificateVerifyParser(0, message, ProtocolVersion.TLS12);
        CertificateVerifyMessage certVerifyMessage = parser.parse();
        assertTrue(certVerifyMessage.getLength().getValue() == length);
        assertTrue(certVerifyMessage.getType().getValue() == type.getValue());
        assertArrayEquals(message, certVerifyMessage.getCompleteResultingMessage().getValue());
        assertArrayEquals(sigHashAlgo, certVerifyMessage.getSignatureHashAlgorithm().getValue());
        assertTrue(signatureLength == certVerifyMessage.getSignatureLength().getValue());
        assertArrayEquals(signature, certVerifyMessage.getSignature().getValue());
    }

}
