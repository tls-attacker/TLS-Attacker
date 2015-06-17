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

import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.util.BigIntegers;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DHEServerKeyExchangeHandler extends HandshakeMessageHandler<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(DHEServerKeyExchangeHandler.class);

    public DHEServerKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = DHEServerKeyExchangeMessage.class;
    }

    /**
     * @param message
     * @param pointer
     * @return
     */
    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue()) {
	    throw new InvalidMessageTypeException(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	}
	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
	int pLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setpLength(pLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + protocolMessage.getpLength().getValue();
	BigInteger p = new BigInteger(1, Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setP(p);

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
	int gLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setgLength(gLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + protocolMessage.getgLength().getValue();
	BigInteger g = new BigInteger(1, Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setG(g);

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
	int publicKeyLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setPublicKeyLength(publicKeyLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + protocolMessage.getPublicKeyLength().getValue();
	BigInteger publicKey = new BigInteger(1, Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setPublicKey(publicKey);

	byte[] dhParams = ArrayConverter
		.concatenate(ArrayConverter.intToBytes(protocolMessage.getpLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), BigIntegers.asUnsignedByteArray(protocolMessage.getP()
			.getValue()), ArrayConverter.intToBytes(protocolMessage.getgLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), BigIntegers.asUnsignedByteArray(protocolMessage.getG()
			.getValue()), ArrayConverter.intToBytes(protocolMessage.getPublicKeyLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), BigIntegers.asUnsignedByteArray(protocolMessage
			.getPublicKey().getValue()));
	InputStream is = new ByteArrayInputStream(dhParams);

	try {
	    ServerDHParams publicKeyParameters = ServerDHParams.parse(is);

	    tlsContext.setServerDHParameters(publicKeyParameters);

	    currentPointer = nextPointer;
	    nextPointer++;
	    HashAlgorithm ha = HashAlgorithm.getHashAlgorithm(message[currentPointer]);
	    protocolMessage.setHashAlgorithm(ha.getValue());

	    currentPointer = nextPointer;
	    nextPointer++;
	    SignatureAlgorithm sa = SignatureAlgorithm.getSignatureAlgorithm(message[currentPointer]);
	    protocolMessage.setSignatureAlgorithm(sa.getValue());

	    currentPointer = nextPointer;
	    nextPointer = currentPointer + HandshakeByteLength.SIGNATURE_LENGTH;
	    int signatureLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	    protocolMessage.setSignatureLength(signatureLength);

	    currentPointer = nextPointer;
	    nextPointer = currentPointer + signatureLength;
	    protocolMessage.setSignature(Arrays.copyOfRange(message, currentPointer, nextPointer));

	    protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	    return nextPointer;
	} catch (IOException ex) {
	    throw new WorkflowExecutionException("DH public key parsing failed", ex);
	}
    }

    @Override
    public byte[] prepareMessageAction() {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
