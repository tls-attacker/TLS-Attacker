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

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields.HandshakeMessageFields;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class ClientHelloHandlerTest {

    static byte[] clientHelloWithoutExtensionBytes = ArrayConverter.hexStringToByteArray("01000059030336CCE3E132A0C5B5"
	    + "DE2C0560B4FF7F6CDF7AE226120E4A99C07E2D9B68B275BB20FA6F8E9770106A"
	    + "CE8ACAB73E18B5D867CAF8AF7E206EF496F23A206A379FC7110012C02BC02FC0" + "0AC009C013C014002F0035000A0100");

    ClientHelloHandler handler;

    public ClientHelloHandlerTest() {
	handler = new ClientHelloHandler(new TlsContext());
    }

    /**
     * Test of prepareMessageAction method, of class ClientHelloHandler.
     */
    @Test
    public void testPrepareMessage() {
	handler.initializeProtocolMessage();

	ClientHelloMessage message = (ClientHelloMessage) handler.getProtocolMessage();

	List<CipherSuite> cipherSuites = new ArrayList();
	cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
	message.setSupportedCipherSuites(cipherSuites);

	List<CompressionMethod> compressionMethods = new ArrayList();
	compressionMethods.add(CompressionMethod.NULL);
	message.setSupportedCompressionMethods(compressionMethods);

	byte[] returned = handler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.CLIENT_HELLO.getValue() },
		new byte[] { 0x00, 0x00, 0x29 }, ProtocolVersion.TLS12.getValue(), message.getUnixTime().getValue(),
		message.getRandom().getValue(), new byte[] { 0x00, 0x00, 0x02 },
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.getValue(),
		new byte[] { 0x01, CompressionMethod.NULL.getValue() });

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    @Test
    public void testParseMessageAction() {
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(clientHelloWithoutExtensionBytes, 0);
	ClientHelloMessage message = (ClientHelloMessage) handler.getProtocolMessage();

	byte[] expectedRandom = ArrayConverter
		.hexStringToByteArray("36cce3e132a0c5b5de2c0560b4ff7f6cdf7ae226120e4a99c07e2d9b68b275bb");
	byte[] actualRandom = ArrayConverter.concatenate(message.getUnixTime().getValue(), message.getRandom()
		.getValue());
	byte[] expectedSessionID = ArrayConverter
		.hexStringToByteArray("fa6f8e9770106ace8acab73e18b5d867caf8af7e206ef496f23a206a379fc711");
	byte[] actualSessionID = message.getSessionId().getValue();
	byte[] expectedCipherSuites = ArrayConverter.hexStringToByteArray("c02bc02fc00ac009c013c014002f0035000a");
	byte[] actualCipherSuites = message.getCipherSuites().getValue();
	HandshakeMessageFields handshakeMessageFields = message.getMessageFields();

	assertEquals("Check message type", HandshakeMessageType.CLIENT_HELLO, message.getHandshakeMessageType());
	assertEquals("Message length should be 508 bytes", new Integer(89), handshakeMessageFields.getLength()
		.getValue());
	assertArrayEquals("Check Protocol Version", ProtocolVersion.TLS12.getValue(), message.getProtocolVersion()
		.getValue());
	assertArrayEquals("Check random", expectedRandom, actualRandom);
	assertEquals("Check session_id length", new Integer(32), message.getSessionIdLength().getValue());
	assertArrayEquals("Check session_id", expectedSessionID, actualSessionID);
	assertEquals("Check cipher_suites length", new Integer(18), message.getCipherSuiteLength().getValue());
	assertArrayEquals("Check cipher_suites", expectedCipherSuites, actualCipherSuites);
	assertEquals("Check compressions length", new Integer(1), message.getCompressionLength().getValue());
	assertArrayEquals("Check compressions", new byte[] { 0x00 }, message.getCompressions().getValue());
	assertEquals("Check protocol message length pointer", clientHelloWithoutExtensionBytes.length, endPointer);
    }
}
