/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class ECDHEServerKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("0c0000900300174104a0da435d1657c12c86a3d232b2c94dfc11989074e5d5813cd46a6cbc63ade1b56dbacfb858c4a4e41188be99bb9d013aec89533b673d1b8d5784387dc0643544060300473045022100ca55fbccc20be69f6ed60d14c97a317efe2c36ba0eb2a6fc4428b83f2228ea14022036d5fc5aa9528b184e12ec628b018a314b7990f0fd894054833c04c093d2599e"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("0c0000900300174104a0da435d1657c12c86a3d232b2c94dfc11989074e5d5813cd46a6cbc63ade1b56dbacfb858c4a4e41188be99bb9d013aec89533b673d1b8d5784387dc0643544060300473045022100ca55fbccc20be69f6ed60d14c97a317efe2c36ba0eb2a6fc4428b83f2228ea14022036d5fc5aa9528b184e12ec628b018a314b7990f0fd894054833c04c093d2599e"),
                        HandshakeMessageType.SERVER_KEY_EXCHANGE,
                        144,
                        (byte) 0x03,
                        ArrayConverter.hexStringToByteArray("0017"),
                        65,
                        ArrayConverter
                                .hexStringToByteArray("04a0da435d1657c12c86a3d232b2c94dfc11989074e5d5813cd46a6cbc63ade1b56dbacfb858c4a4e41188be99bb9d013aec89533b673d1b8d5784387dc0643544"),
                        (byte) 0x06,
                        (byte) 0x03,
                        71,
                        ArrayConverter
                                .hexStringToByteArray("3045022100ca55fbccc20be69f6ed60d14c97a317efe2c36ba0eb2a6fc4428b83f2228ea14022036d5fc5aa9528b184e12ec628b018a314b7990f0fd894054833c04c093d2599e"), }, });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;
    private byte curveType;
    private byte[] namedCurve;
    private int pubKeyLength;
    private byte[] pubKey;
    private byte hashAlgorithm;
    private byte signatureAlgorithm;
    private int sigLength;
    private byte[] signature;

    public ECDHEServerKeyExchangeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte curveType, byte[] namedCurve, int pubKeyLength, byte[] pubKey, byte hashAlgorithm,
            byte signatureAlgorithm, int sigLength, byte[] signature) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.curveType = curveType;
        this.namedCurve = namedCurve;
        this.pubKeyLength = pubKeyLength;
        this.pubKey = pubKey;
        this.hashAlgorithm = hashAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.sigLength = sigLength;
        this.signature = signature;
    }

    /**
     * Test of parse method, of class ECDHEServerKeyExchangeParser.
     */
    @Test
    public void testParse() {
        ECDHEServerKeyExchangeParser parser = new ECDHEServerKeyExchangeParser(start, message);
        ECDHEServerKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(length == msg.getLength().getValue());
        assertTrue(type.getValue() == msg.getType().getValue());
        assertTrue(curveType == msg.getCurveType().getValue());
        assertArrayEquals(namedCurve, msg.getNamedCurve().getValue());
        assertTrue(pubKeyLength == msg.getSerializedPublicKeyLength().getValue());
        assertArrayEquals(pubKey, msg.getSerializedPublicKey().getValue());
        assertTrue(signatureAlgorithm == msg.getSignatureAlgorithm().getValue());
        assertTrue(hashAlgorithm == msg.getHashAlgorithm().getValue());
        assertTrue(sigLength == msg.getSignatureLength().getValue());
        assertArrayEquals(signature, msg.getSignature().getValue());
    }
}
