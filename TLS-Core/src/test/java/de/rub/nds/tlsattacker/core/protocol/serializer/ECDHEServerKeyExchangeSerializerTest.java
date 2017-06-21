/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class ECDHEServerKeyExchangeSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ECDHEServerKeyExchangeParserTest.generateData();
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
    private Byte hashAlgorithm;
    private Byte signatureAlgorithm;
    private int sigLength;
    private byte[] signature;
    private ProtocolVersion version;

    public ECDHEServerKeyExchangeSerializerTest(byte[] message, HandshakeMessageType type, int length, byte curveType,
            byte[] namedCurve, int pubKeyLength, byte[] pubKey, Byte hashAlgorithm, Byte signatureAlgorithm,
            int sigLength, byte[] signature, ProtocolVersion version) {
        this.message = message;
        this.start = 0;
        this.expectedPart = message;
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
        this.version = version;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * ECDHEServerKeyExchangeSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        ECDHEServerKeyExchangeMessage msg = new ECDHEServerKeyExchangeMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setCurveType(curveType);
        msg.setLength(length);
        msg.setType(type.getValue());
        msg.setNamedCurve(namedCurve);
        msg.setSerializedPublicKey(pubKey);
        msg.setSerializedPublicKeyLength(pubKeyLength);
        if (hashAlgorithm != null) {
            msg.setHashAlgorithm(hashAlgorithm);
        }
        if (signatureAlgorithm != null) {
            msg.setSignatureAlgorithm(signatureAlgorithm);
        }
        msg.setSignatureLength(sigLength);
        msg.setSignature(signature);
        ECDHEServerKeyExchangeSerializer serializer = new ECDHEServerKeyExchangeSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
