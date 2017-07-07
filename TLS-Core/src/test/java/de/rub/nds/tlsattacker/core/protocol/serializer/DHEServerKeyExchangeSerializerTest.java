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
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParserTest;
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
public class DHEServerKeyExchangeSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return DHEServerKeyExchangeParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;
    private int pLength;
    private byte[] p;
    private int gLength;
    private byte[] g;
    private int serializedKeyLength;
    private byte[] serializedKey;
    private byte[] signatureAndHashAlgo;
    private int sigLength;
    private byte[] signature;
    private ProtocolVersion version;

    public DHEServerKeyExchangeSerializerTest(byte[] message, HandshakeMessageType type, int length, int pLength,
            byte[] p, int gLength, byte[] g, int serializedKeyLength, byte[] serializedKey,
            byte[] signatureAndHashAlgo, int sigLength, byte[] signature, ProtocolVersion version) {
        this.message = message;
        this.start = 0;
        this.expectedPart = message;
        this.type = type;
        this.length = length;
        this.pLength = pLength;
        this.p = p;
        this.gLength = gLength;
        this.g = g;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.signatureAndHashAlgo = signatureAndHashAlgo;
        this.sigLength = sigLength;
        this.signature = signature;
        this.version = version;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * DHEServerKeyExchangeSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        DHEServerKeyExchangeMessage msg = new DHEServerKeyExchangeMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setType(type.getValue());
        msg.setLength(length);
        msg.setpLength(pLength);
        msg.setP(p);
        msg.setgLength(gLength);
        msg.setG(g);
        msg.setSerializedPublicKey(serializedKey);
        msg.setSerializedPublicKeyLength(serializedKeyLength);
        msg.setSignature(signature);
        if (signatureAndHashAlgo != null) {
            msg.setSignatureAndHashAlgorithm(signatureAndHashAlgo);
        }
        msg.setSignatureLength(sigLength);
        DHEServerKeyExchangeSerializer serializer = new DHEServerKeyExchangeSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serialize());

    }

}
