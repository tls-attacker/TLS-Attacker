/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.serializer.DHEServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParserTest;
import java.math.BigInteger;
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
    private byte hashAlgo;
    private byte sigAlgo;
    private int sigLength;
    private byte[] signature;

    public DHEServerKeyExchangeSerializerTest(byte[] message, int start, byte[] expectedPart,
            HandshakeMessageType type, int length, int pLength, byte[] p, int gLength, byte[] g,
            int serializedKeyLength, byte[] serializedKey, byte hashAlgo, byte sigAlgo, int sigLength, byte[] signature) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.pLength = pLength;
        this.p = p;
        this.gLength = gLength;
        this.g = g;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.hashAlgo = hashAlgo;
        this.sigAlgo = sigAlgo;
        this.sigLength = sigLength;
        this.signature = signature;
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
        msg.setModulusLength(pLength);
        msg.setModulus(p);
        msg.setGeneratorLength(gLength);
        msg.setGenerator(g);
        msg.setPublicKey(serializedKey);
        msg.setPublicKeyLength(serializedKeyLength);
        msg.setSignature(signature);
        msg.setSignatureAlgorithm(sigAlgo);
        msg.setHashAlgorithm(hashAlgo);
        msg.setSignatureLength(sigLength);
        DHEServerKeyExchangeSerializer serializer = new DHEServerKeyExchangeSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());

    }

}
