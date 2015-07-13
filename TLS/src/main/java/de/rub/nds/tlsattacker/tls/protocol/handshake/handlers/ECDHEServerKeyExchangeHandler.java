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

import de.rub.nds.tlsattacker.tls.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.ECCurveType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields.HandshakeMessageFields;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHEServerKeyExchangeHandler extends HandshakeMessageHandler<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ECDHEServerKeyExchangeHandler.class);

    public ECDHEServerKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ECDHEServerKeyExchangeMessage.class;
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
	HandshakeMessageFields protocolMessageFields = protocolMessage.getMessageFields();

	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessageFields.setLength(length);

	currentPointer = nextPointer;
	nextPointer++;
	ECCurveType ct = ECCurveType.getCurveType(message[currentPointer]);
	if (ct != ECCurveType.NAMED_CURVE) {
	    throw new UnsupportedOperationException("Currently only named curves are supported");
	}
	protocolMessage.setCurveType(ct.getValue());

	currentPointer = nextPointer;
	nextPointer = currentPointer + NamedCurve.LENGTH;
	NamedCurve nc = NamedCurve.getNamedCurve(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setNamedCurve(nc.getValue());

	currentPointer = nextPointer;
	nextPointer++;
	int publicKeyLength = message[currentPointer] & 0xFF;
	protocolMessage.setPublicKeyLength(publicKeyLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + publicKeyLength;
	protocolMessage.setPublicKey(Arrays.copyOfRange(message, currentPointer, nextPointer));

	byte[] ecParams = ArrayConverter.concatenate(new byte[] { protocolMessage.getCurveType().getValue() },
		protocolMessage.getNamedCurve().getValue(), ArrayConverter.intToBytes(protocolMessage
			.getPublicKeyLength().getValue(), 1), protocolMessage.getPublicKey().getValue());
	InputStream is = new ByteArrayInputStream(ecParams);

	try {
	    ECPublicKeyParameters publicKeyParameters = ECCUtilsBCWrapper.readECParametersWithPublicKey(is);
	    LOGGER.debug("Parsed the following EC domain parameters: ");
	    LOGGER.debug("  Curve order: {}", publicKeyParameters.getParameters().getCurve().getOrder());
	    LOGGER.debug("  Parameter A: {}", publicKeyParameters.getParameters().getCurve().getA());
	    LOGGER.debug("  Parameter B: {}", publicKeyParameters.getParameters().getCurve().getB());
	    LOGGER.debug("  Base point: {} ", publicKeyParameters.getParameters().getG());
	    LOGGER.debug("  Public key point Q: {} ", publicKeyParameters.getQ());

	    tlsContext.getEcContext().setServerPublicKeyParameters(publicKeyParameters);

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
	    ex.printStackTrace();
	    throw new WorkflowExecutionException("EC public key parsing failed", ex);
	}
    }

    @Override
    public byte[] prepareMessageAction() {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
