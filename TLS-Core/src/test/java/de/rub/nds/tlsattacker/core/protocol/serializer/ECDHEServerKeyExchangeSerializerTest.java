/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.serializer.ECDHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParserTest;
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
    private byte hashAlgorithm;
    private byte signatureAlgorithm;
    private int sigLength;
    private byte[] signature;

    public ECDHEServerKeyExchangeSerializerTest(byte[] message, int start, byte[] expectedPart,
            HandshakeMessageType type, int length, byte curveType, byte[] namedCurve, int pubKeyLength, byte[] pubKey,
            byte hashAlgorithm, byte signatureAlgorithm, int sigLength, byte[] signature) {
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
        msg.setHashAlgorithm(hashAlgorithm);
        msg.setSignatureAlgorithm(signatureAlgorithm);
        msg.setSignatureLength(sigLength);
        msg.setSignature(signature);
        ECDHEServerKeyExchangeSerializer serializer = new ECDHEServerKeyExchangeSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
