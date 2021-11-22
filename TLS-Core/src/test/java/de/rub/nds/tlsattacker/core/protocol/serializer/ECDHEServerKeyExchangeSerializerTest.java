/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHEServerKeyExchangeSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ECDHEServerKeyExchangeParserTest.generateData();
    }

    private final byte[] expectedPart;
    private final byte curveType;
    private final byte[] namedGroup;
    private final int pubKeyLength;
    private final byte[] pubKey;
    private final byte[] signatureAndHashAlgo;
    private final int sigLength;
    private final byte[] signature;
    private final ProtocolVersion version;

    public ECDHEServerKeyExchangeSerializerTest(byte[] message, byte curveType, byte[] namedGroup, int pubKeyLength,
        byte[] pubKey, byte[] signatureAndHashAlgo, int sigLength, byte[] signature, ProtocolVersion version) {
        this.expectedPart = message;
        this.curveType = curveType;
        this.namedGroup = namedGroup;
        this.pubKeyLength = pubKeyLength;
        this.pubKey = pubKey;
        this.signatureAndHashAlgo = signatureAndHashAlgo;
        this.sigLength = sigLength;
        this.signature = signature;
        this.version = version;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class ECDHEServerKeyExchangeSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        ECDHEServerKeyExchangeMessage msg = new ECDHEServerKeyExchangeMessage();
        msg.setCompleteResultingMessage(expectedPart);
        msg.setCurveType(curveType);
        msg.setNamedGroup(namedGroup);
        msg.setPublicKey(pubKey);
        msg.setPublicKeyLength(pubKeyLength);
        if (signatureAndHashAlgo != null) {
            msg.setSignatureAndHashAlgorithm(signatureAndHashAlgo);
        }
        msg.setPublicKey(pubKey);
        msg.setPublicKeyLength(pubKeyLength);
        msg.setSignatureLength(sigLength);
        msg.setSignature(signature);
        ECDHEServerKeyExchangeSerializer serializer = new ECDHEServerKeyExchangeSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
