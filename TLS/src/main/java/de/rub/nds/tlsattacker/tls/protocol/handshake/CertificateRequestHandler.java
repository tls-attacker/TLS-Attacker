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
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.LinkedList;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */

/**
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
	// TODO parse Arguments from Console and set properties with
	// Confighandler

	byte[] clientCertificateTypes = { ClientCertificateType.RSA_SIGN.getValue() };
	protocolMessage.setClientCertificateTypes(clientCertificateTypes);

	int clientCertificateTypesCount = protocolMessage.getClientCertificateTypes().getValue().length;
	protocolMessage.setClientCertificateTypesCount(clientCertificateTypesCount);

	byte[] signatureAndHashAlgorithms = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512)
		.getValue();
	signatureAndHashAlgorithms = ArrayConverter.concatenate(signatureAndHashAlgorithms,
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA384).getValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA256).getValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA224).getValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1).getValue(),
		new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.MD5).getValue());
	protocolMessage.setSignatureHashAlgorithms(signatureAndHashAlgorithms);

	int signatureAndHashAlgorithmsCount = protocolMessage.getSignatureHashAlgorithms().getValue().length;
	protocolMessage.setSignatureHashAlgorithmsLength(signatureAndHashAlgorithmsCount);

	int distinguishedNamesLength = 0;
	protocolMessage.setDistinguishedNamesLength(distinguishedNamesLength);

	byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage
		.getClientCertificateTypesCount().getValue(), 1), protocolMessage.getClientCertificateTypes()
		.getValue(), ArrayConverter.intToBytes(protocolMessage.getSignatureHashAlgorithmsLength().getValue(),
		HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH), protocolMessage.getSignatureHashAlgorithms()
		.getValue(), ArrayConverter.intToBytes(protocolMessage.getDistinguishedNamesLength().getValue(),
		HandshakeByteLength.DISTINGUISHED_NAMES_LENGTH));

	HandshakeMessageFields protocolMessageFields = protocolMessage.getMessageFields();

	protocolMessageFields.setLength(result.length);

	long header = (HandshakeMessageType.CERTIFICATE_REQUEST.getValue() << 24)
		+ protocolMessageFields.getLength().getValue();

	protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		ArrayConverter.longToUint32Bytes(header), result));

	return protocolMessage.getCompleteResultingMessage().getValue();

    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.CERTIFICATE_REQUEST.getValue()) {
	    throw new InvalidMessageTypeException("This is not a Certificate Request message");
	}
	HandshakeMessageFields protocolMessageFields = protocolMessage.getMessageFields();

	protocolMessage.setType(message[pointer]);
	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;

	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessageFields.setLength(length);
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
