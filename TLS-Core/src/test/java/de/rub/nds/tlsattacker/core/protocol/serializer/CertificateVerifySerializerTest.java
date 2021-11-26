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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateVerifyMessageParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateVerifySerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CertificateVerifyMessageParserTest.generateData();
    }

    private final byte[] expectedPart;
    private final byte[] sigHashAlgo;
    private final int signatureLength;
    private final byte[] signature;

    public CertificateVerifySerializerTest(byte[] message, byte[] sigHashAlgo, int signatureLength, byte[] signature) {
        this.expectedPart = message;
        this.sigHashAlgo = sigHashAlgo;
        this.signatureLength = signatureLength;
        this.signature = signature;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class CertificateVerifySerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        CertificateVerifyMessage message = new CertificateVerifyMessage();
        message.setSignature(signature);
        message.setSignatureLength(signatureLength);
        message.setSignatureHashAlgorithm(sigHashAlgo);
        CertificateVerifySerializer serializer = new CertificateVerifySerializer(message, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serializeProtocolMessageContent());
    }

}
