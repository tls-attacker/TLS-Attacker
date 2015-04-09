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

import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.LinkedList;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <HandshakeMessage>
 */
public class CertificateRequestHandler<HandshakeMessage extends CertificateRequestMessage> extends
	HandshakeMessageHandler<HandshakeMessage> {

    public CertificateRequestHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = CertificateRequestMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.CERTIFICATE_REQUEST.getValue()) {
	    throw new InvalidMessageTypeException("This is not a Certificate Request message");
	}
	protocolMessage.setType(message[pointer]);
	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;

	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);
	currentPointer = nextPointer;

	nextPointer = currentPointer + 1;
	int certificateTypesCount = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setClientCertificateTypesCount(certificateTypesCount);
	currentPointer = nextPointer;

	nextPointer = currentPointer + certificateTypesCount;
	protocolMessage.setClientCertificateTypes(Arrays.copyOfRange(message, currentPointer, nextPointer));
	currentPointer = nextPointer;

	nextPointer = currentPointer + HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH;
	int signatureHashAlgorithmsLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer,
		nextPointer));
	protocolMessage.setSignatureHashAlgorithmsLength(signatureHashAlgorithmsLength);
	currentPointer = nextPointer;

	nextPointer = currentPointer + signatureHashAlgorithmsLength;
	protocolMessage.setSignatureHashAlgorithms(Arrays.copyOfRange(message, currentPointer, nextPointer));
	currentPointer = nextPointer;

	LinkedList<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = new LinkedList<>();
	for (int i = 0; i < protocolMessage.getSignatureHashAlgorithmsLength().getValue() / 2; i++) {
	    SignatureAndHashAlgorithm sha = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(Arrays.copyOfRange(
		    protocolMessage.getSignatureHashAlgorithms().getValue(), i * 2, i * 2 + 2));
	    signatureAndHashAlgorithms.add(sha);
	}
	tlsContext.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

	nextPointer = currentPointer + HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH;
	int distinguishedNamesLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer,
		nextPointer));
	protocolMessage.setDistinguishedNamesLength(distinguishedNamesLength);
	currentPointer = nextPointer;

	nextPointer = currentPointer + distinguishedNamesLength;
	protocolMessage.setDistinguishedNames(Arrays.copyOfRange(message, currentPointer, nextPointer));
	currentPointer = nextPointer;

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	return currentPointer;
    }
}
