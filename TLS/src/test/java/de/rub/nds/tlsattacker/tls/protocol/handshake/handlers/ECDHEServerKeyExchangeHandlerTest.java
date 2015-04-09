/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.ECCurveType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for ECDHE key exchange handler, with values from wireshark
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHEServerKeyExchangeHandlerTest {

    static BigInteger testServerKeyExchangeECDSA = new BigInteger(
	    "0c0000d003000e910404a9c2a82e8f7e90e11c26035f93dae74553334b074484895a7560a5e949251d4c77ebfc4443bb0d9cfe204"
		    + "ca3bd67a8074f32c0ff865fb434f0647c3f1b10072b822c65f924595302f38a1a34dfaaec91e9702aa5658cb506f6d7"
		    + "90aa72a3edea5677a81ea3c6248802b23e88de60659bad8c34f67a4852ec985cdb092ef85b592861372dce0b3f82e7a"
		    + "a76c50b8afe060300373035021876494098e491e52572458f37f47a1f99701e7ae3a3132822021900b6c9e009bb751d"
		    + "ee939b4b50f55f3d9f167283d3f4155f50", 16);

    static BigInteger testServerKeyExchangeRSA = new BigInteger(
	    "0c00011903000e9104053bca98c5a607ab9cb2449c9467c8001d891524383351066c903c62477c4d0c8bb370e2c1e96caf1500de8"
		    + "fa9d5c85b82a0be5bb868f7e6e5a91cbfa3fc82c7864eab5bb508c23202c5217297dcd658578e48ec0c8b4a09449341"
		    + "4f74315557f6daf25eba4c3c4006a64e9ed18788539c5e6a4abeeba1167424c106fea33ff2a65ed756220d4f62b4c78"
		    + "79ba09d85150601008011d246b6b74076f697d45447dadd6aeaaef298fc8fa48a0237dac8639a6e3bfeffae3bd2ee6a"
		    + "4f786ee9f76b52c7df82f3b9d23b49f8934f29ea3c1f2dc4a016066ab9e05277ba4a41e85a38d35c0537155bc0f3865"
		    + "87d61f819970c7ae7918940a05308758253deb71f8d7d18fd540e372dba7829f6d86a38c20e60f50500b1", 16);

    ECDHEServerKeyExchangeHandler handler;

    public ECDHEServerKeyExchangeHandlerTest() {
	handler = new ECDHEServerKeyExchangeHandler(new TlsContext());
    }

    /**
     * Test of parseMessageAction method, of class
     * ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testParseMessageECDSA() {
	byte[] serverKeyExchangeBytes = testServerKeyExchangeECDSA.toByteArray();
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(serverKeyExchangeBytes, 0);
	ECDHEServerKeyExchangeMessage message = (ECDHEServerKeyExchangeMessage) handler.getProtocolMessage();

	assertEquals("Message type must be ServerKeyExchange", HandshakeMessageType.SERVER_KEY_EXCHANGE,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 208", new Integer(208), message.getLength().getValue());
	assertEquals("Curve Type must be named curve", ECCurveType.NAMED_CURVE,
		ECCurveType.getCurveType(message.getCurveType().getValue()));
	assertEquals("Named Curve must be sect571r1", NamedCurve.SECT571R1,
		NamedCurve.getNamedCurve(message.getNamedCurve().getValue()));
	assertEquals("Public key length is 145", new Integer(145), message.getPublicKeyLength().getValue());
	assertEquals("Hash must be SHA512", HashAlgorithm.SHA512,
		HashAlgorithm.getHashAlgorithm(message.getHashAlgorithm().getValue()));
	assertEquals("Signature must be ECDSA", SignatureAlgorithm.ECDSA,
		SignatureAlgorithm.getSignatureAlgorithm(message.getSignatureAlgorithm().getValue()));
	assertEquals("Signature length must be 55", new Integer(55), message.getSignatureLength().getValue());

	assertEquals("The pointer has to return the length of the protocol message", serverKeyExchangeBytes.length,
		endPointer);
    }

    /**
     * Test of parseMessageAction method, of class
     * ECDHEServerKeyExchangeHandler.
     */
    @Test
    public void testParseMessageRSA() {
	byte[] serverKeyExchangeBytes = testServerKeyExchangeRSA.toByteArray();
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(serverKeyExchangeBytes, 0);
	ECDHEServerKeyExchangeMessage message = (ECDHEServerKeyExchangeMessage) handler.getProtocolMessage();

	assertEquals("Message type must be ServerKeyExchange", HandshakeMessageType.SERVER_KEY_EXCHANGE,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 281", new Integer(281), message.getLength().getValue());
	assertEquals("Curve Type must be named curve", ECCurveType.NAMED_CURVE,
		ECCurveType.getCurveType(message.getCurveType().getValue()));
	assertEquals("Named Curve must be sect571r1", NamedCurve.SECT571R1,
		NamedCurve.getNamedCurve(message.getNamedCurve().getValue()));
	assertEquals("Public key length is 145", new Integer(145), message.getPublicKeyLength().getValue());
	assertEquals("Hash must be SHA512", HashAlgorithm.SHA512,
		HashAlgorithm.getHashAlgorithm(message.getHashAlgorithm().getValue()));
	assertEquals("Signature must be RSA", SignatureAlgorithm.RSA,
		SignatureAlgorithm.getSignatureAlgorithm(message.getSignatureAlgorithm().getValue()));
	assertEquals("Signature length must be 128", new Integer(128), message.getSignatureLength().getValue());

	assertEquals("The pointer has to return the length of the protocol message", serverKeyExchangeBytes.length,
		endPointer);
    }

    @Test
    public void testIsCorrectProtocolMessage() {
	ECDHEServerKeyExchangeMessage sem = new ECDHEServerKeyExchangeMessage();
	assertTrue(handler.isCorrectProtocolMessage(sem));

	CertificateMessage cm = new CertificateMessage();
	assertFalse(handler.isCorrectProtocolMessage(cm));
    }
}
