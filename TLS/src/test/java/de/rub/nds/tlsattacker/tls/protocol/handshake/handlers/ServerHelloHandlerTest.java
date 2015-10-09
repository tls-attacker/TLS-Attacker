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
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields.HandshakeMessageFields;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerHelloHandlerTest {

    static byte[] serverKeyExchangeWithoutExtensionBytes = ArrayConverter
	    .hexStringToByteArray("02000046030354cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d5720682200"
		    + "00ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0c01300");

    ServerHelloHandler handler;

    TlsContext tlsContext;

    public ServerHelloHandlerTest() {
	tlsContext = new TlsContext();
	tlsContext.setProtocolVersion(ProtocolVersion.TLS12);
	handler = new ServerHelloHandler(tlsContext);
    }

    /**
     * Test of parseMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testParseMessage() {
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(serverKeyExchangeWithoutExtensionBytes, 0);
	ServerHelloMessage message = (ServerHelloMessage) handler.getProtocolMessage();
	HandshakeMessageFields handshakeMessageFields = message.getMessageFields();

	assertEquals("Message type must be ServerHello", HandshakeMessageType.SERVER_HELLO,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 70", new Integer(70), handshakeMessageFields.getLength().getValue());
	assertEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12, tlsContext.getProtocolVersion());
	assertArrayEquals(
		"Server Session ID",
		ArrayConverter.hexStringToByteArray("68220000ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0"),
		message.getSessionId().getValue());
	assertArrayEquals(
		"Server Random",
		ArrayConverter.hexStringToByteArray("54cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d57"),
		tlsContext.getServerRandom());
	assertEquals("Ciphersuite must be TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tlsContext.getSelectedCipherSuite());
	assertEquals("Compression must be null", CompressionMethod.NULL, tlsContext.getCompressionMethod());

	assertEquals("The pointer has to return the length of this message + starting position",
		serverKeyExchangeWithoutExtensionBytes.length, endPointer);
    }

    /**
     * Test of parseMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testParseMessageWithExtensions() {
	// TODO
    }

}
