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
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
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
public class CertificateVerifyMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { {}, {} });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private byte[] sigHashAlgo;
    private int signatureLength;
    private byte[] signature;

    public CertificateVerifyMessageParserTest(byte[] message, int start, byte[] expectedPart,
            HandshakeMessageType type, int length, byte[] sigHashAlgo, int signatureLength, byte[] signature) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.sigHashAlgo = sigHashAlgo;
        this.signatureLength = signatureLength;
        this.signature = signature;
    }

    /**
     * Test of parse method, of class CertificateVerifyMessageParser.
     */
    @Test
    public void testParse() {
        CertificateVerifyMessageParser parser = new CertificateVerifyMessageParser(start, message);
        CertificateVerifyMessage certVerifyMessage = parser.parse();
        assertTrue(certVerifyMessage.getLength().getValue() == length);
        assertTrue(certVerifyMessage.getType().getValue() == type.getValue());
        assertArrayEquals(expectedPart, certVerifyMessage.getCompleteResultingMessage().getValue());
        assertArrayEquals(sigHashAlgo, certVerifyMessage.getSignatureHashAlgorithm().getValue());
        assertTrue(signatureLength == certVerifyMessage.getSignatureLength().getValue());
        assertArrayEquals(signature, certVerifyMessage.getSignature().getValue());
    }

}
