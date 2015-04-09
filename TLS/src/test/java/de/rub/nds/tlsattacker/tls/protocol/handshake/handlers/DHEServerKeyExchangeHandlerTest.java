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

import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for ECDHE key exchange handler, with values from wireshark
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DHEServerKeyExchangeHandlerTest {

    static BigInteger testServerKeyExchangeDSA = new BigInteger(
	    "0c0000b90040da583c16d9852289d0e4af756f4cca92dd4be533b804fb0fed94ef9c8a4403ed574650d36999db29d776276ba2d3d"
		    + "412e218f4dd1e084cf6d8003e7c4774e833000102004006a14fecf0b2e7fae2b30d879616207fb1022ce1000d87c3e9"
		    + "8ede5a053799d61adc622daac01b0966232425784ffd3493f2ab3bfa109361a42c28c7ba4af76c0402002e302c02144"
		    + "f232c10ad1fcfb92b3bedc7c0deddd5c04908ad02142211f07d891eb18a1e0d58dfba4949ffe5961451", 16);

    static BigInteger testServerKeyExchangeRSA = new BigInteger("0", 16);

    DHEServerKeyExchangeHandler handler;

    public DHEServerKeyExchangeHandlerTest() {
	handler = new DHEServerKeyExchangeHandler(new TlsContext());
    }

    /**
     * Test of parseMessageAction method, of class DHEServerKeyExchangeHandler.
     */
    @Test
    public void testParseMessageDSA() {
	byte[] serverKeyExchangeBytes = testServerKeyExchangeDSA.toByteArray();
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(serverKeyExchangeBytes, 0);
	DHEServerKeyExchangeMessage message = (DHEServerKeyExchangeMessage) handler.getProtocolMessage();

	assertEquals("Message type must be ServerKeyExchange", HandshakeMessageType.SERVER_KEY_EXCHANGE,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 185", new Integer(185), message.getLength().getValue());
	assertEquals("p length must be 64", new Integer(64), message.getpLength().getValue());
	assertEquals("g length must be ", new Integer(1), message.getgLength().getValue());
	assertEquals("g must be 2", new BigInteger("2"), message.getG().getValue());

	assertEquals("Public key length is 64", new Integer(64), message.getPublicKeyLength().getValue());
	assertEquals("Hash must be SHA256", HashAlgorithm.SHA256,
		HashAlgorithm.getHashAlgorithm(message.getHashAlgorithm().getValue()));
	assertEquals("Signature must be DSA", SignatureAlgorithm.DSA,
		SignatureAlgorithm.getSignatureAlgorithm(message.getSignatureAlgorithm().getValue()));
	assertEquals("Signature length must be 46", new Integer(46), message.getSignatureLength().getValue());

	assertEquals("The pointer has to return the length of the protocol message", serverKeyExchangeBytes.length,
		endPointer);
    }

    @Test
    public void testIsCorrectProtocolMessage() {
	DHEServerKeyExchangeMessage sem = new DHEServerKeyExchangeMessage();
	assertTrue(handler.isCorrectProtocolMessage(sem));

	CertificateMessage cm = new CertificateMessage();
	assertFalse(handler.isCorrectProtocolMessage(cm));
    }
}
