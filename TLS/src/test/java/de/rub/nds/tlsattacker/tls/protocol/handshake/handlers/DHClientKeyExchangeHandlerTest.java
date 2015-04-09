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

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.math.BigInteger;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DHClientKeyExchangeHandlerTest {

    static BigInteger publicKey = new BigInteger(
	    "6b7123248ca29efc8baea75d4f4321f58c072281e9f8217ae19750b5000714b24aa603ed61eb"
		    + "2c6d4a047922a0ba48dcfc57552ad137a39c1078e92a2da74b19", 16);

    DHClientKeyExchangeHandler handler;

    DHEServerKeyExchangeHandler skeHandler;

    public DHClientKeyExchangeHandlerTest() {
	TlsContext context = new TlsContext();
	context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
	context.setProtocolVersion(ProtocolVersion.TLS12);
	handler = new DHClientKeyExchangeHandler(context);

	// initialize tls context with dh parameters
	skeHandler = new DHEServerKeyExchangeHandler(context);
	byte[] serverKeyExchangeBytes = DHEServerKeyExchangeHandlerTest.testServerKeyExchangeDSA.toByteArray();
	skeHandler.initializeProtocolMessage();
	skeHandler.parseMessageAction(serverKeyExchangeBytes, 0);
    }

    /**
     * Test of prepareMessageAction method, of class
     * ECDHClientKeyExchangeHandler.
     */
    @Test
    public void testPrepareMessage() {
	handler.initializeProtocolMessage();

	DHClientKeyExchangeMessage message = (DHClientKeyExchangeMessage) handler.getProtocolMessage();
	ModifiableVariable<BigInteger> y = new ModifiableVariable<>();
	y.setModification(BigIntegerModificationFactory.explicitValue(publicKey));
	message.setY(y);

	// byte[] result = handler.prepareMessageAction();
	//
	// assertEquals("Message type must be ClientKeyExchange",
	// HandshakeMessageType.CLIENT_KEY_EXCHANGE,
	// message.getHandshakeMessageType());
	//
	// byte[] serializedPublicKey =
	// BigIntegers.asUnsignedByteArray(publicKey);
	// byte[] expected = ArrayConverter.concatenate(new byte[] { 0x10, 0x00,
	// 0x00, (byte) 0x42, 0x00, (byte) 0x40 },
	// serializedPublicKey);
	//
	// Assert.assertArrayEquals(expected, result);
    }
}
