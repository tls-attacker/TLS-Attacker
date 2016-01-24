/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields.HandshakeMessageFields;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Philip Riese <philip.riese@rub.de>
 */
public class CertificateVerifyHandlerTest {

    CertificateVerifyHandler handler;

    TlsContext tlsContext;

    public CertificateVerifyHandlerTest() {
	tlsContext = new TlsContext();
	handler = new CertificateVerifyHandler(tlsContext);
    }

    /**
     * Test of prepareMessageAction method, of class CertificateVerifyHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	// todo
    }

    /**
     * Test of parseMessageAction method, of class CertificateVerifyHandler.
     */
    @Test
    public void testParseMessageAction() {

	handler.initializeProtocolMessage();

	byte[] inputBytes = { HandshakeMessageType.CERTIFICATE_VERIFY.getValue() };
	byte[] sigHashAlg = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512).getValue();
	inputBytes = ArrayConverter.concatenate(inputBytes, sigHashAlg, new byte[] { 0x00, 0x05 }, new byte[] { 0x25,
		0x26, 0x27, 0x28, 0x29 });
	int endPointer = handler.parseMessageAction(inputBytes, 0);
	CertificateVerifyMessage message = (CertificateVerifyMessage) handler.getProtocolMessage();

	assertNotNull("Confirm endPointer is not 'NULL'", endPointer);
	assertEquals("Confirm actual message length", endPointer, 10);
	assertEquals("Confirm message type", HandshakeMessageType.CERTIFICATE_VERIFY, message.getHandshakeMessageType());
	assertArrayEquals("Confirm SignatureAndHashAlgorithm type", sigHashAlg, message.getSignatureHashAlgorithm()
		.getValue());
	assertTrue("Confirm Signature Length", message.getSignatureLength().getValue() == 5);
	assertTrue("Confirm Signature",
		Arrays.equals(message.getSignature().getValue(), new byte[] { 0x25, 0x26, 0x27, 0x28, 0x29 }));

    }

}
