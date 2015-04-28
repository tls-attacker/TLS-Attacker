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

import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.Time;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <HandshakeMessage>
 */
public class ClientHelloHandler<HandshakeMessage extends ClientHelloMessage> extends
	HandshakeMessageHandler<HandshakeMessage> {

    public ClientHelloHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ClientHelloMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setProtocolVersion(tlsContext.getProtocolVersion().getValue());

	// by default we do not use a session id
	protocolMessage.setSessionId(new byte[0]);
	int length = protocolMessage.getSessionId().getValue().length;
	protocolMessage.setSessionIdLength(length);

	// random handling
	final long unixTime = Time.getUnixTime();
	protocolMessage.setUnixTime(ArrayConverter.longToUint32Bytes(unixTime));

	byte[] random = new byte[HandshakeByteLength.RANDOM];
	RandomHelper.getRandom().nextBytes(random);
	protocolMessage.setRandom(random);

	tlsContext.setClientRandom(ArrayConverter.concatenate(protocolMessage.getUnixTime().getValue(), protocolMessage
		.getRandom().getValue()));

	byte[] cipherSuites = null;
	for (CipherSuite cs : protocolMessage.getSupportedCipherSuites()) {
	    cipherSuites = ArrayConverter.concatenate(cipherSuites, cs.getValue());
	}
	protocolMessage.setCipherSuites(cipherSuites);

	int cipherSuiteLength = protocolMessage.getCipherSuites().getValue().length;
	protocolMessage.setCipherSuiteLength(cipherSuiteLength);

	byte[] compressionMethods = null;
	for (CompressionMethod cm : protocolMessage.getSupportedCompressionMethods()) {
	    compressionMethods = ArrayConverter.concatenate(compressionMethods, cm.getArrayValue());
	}
	protocolMessage.setCompressions(compressionMethods);

	int compressionMethodLength = protocolMessage.getCompressions().getValue().length;
	protocolMessage.setCompressionLength(compressionMethodLength);

	byte[] result = ArrayConverter.concatenate(protocolMessage.getProtocolVersion().getValue(), protocolMessage
		.getUnixTime().getValue(), protocolMessage.getRandom().getValue(), ArrayConverter.intToBytes(
		protocolMessage.getSessionIdLength().getValue(), 1), protocolMessage.getSessionId().getValue(),
		ArrayConverter.intToBytes(protocolMessage.getCipherSuiteLength().getValue(),
			HandshakeByteLength.CIPHER_SUITE), protocolMessage.getCipherSuites().getValue(),
		ArrayConverter.intToBytes(protocolMessage.getCompressionLength().getValue(),
			HandshakeByteLength.COMPRESSION), protocolMessage.getCompressions().getValue());

	byte[] extensionBytes = null;
	for (ExtensionMessage extension : protocolMessage.getExtensions()) {
	    ExtensionHandler handler = extension.getExtensionHandler();
	    handler.initializeClientHelloExtension(extension);
	    extensionBytes = ArrayConverter.concatenate(extensionBytes, extension.getExtensionBytes().getValue());
	}

	if (extensionBytes != null && extensionBytes.length != 0) {
	    byte[] extensionLength = ArrayConverter.intToBytes(extensionBytes.length, ExtensionByteLength.EXTENSIONS);

	    result = ArrayConverter.concatenate(result, extensionLength, extensionBytes);
	}

	protocolMessage.setLength(result.length);

	long header = (HandshakeMessageType.CLIENT_HELLO.getValue() << 24) + protocolMessage.getLength().getValue();

	protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		ArrayConverter.longToUint32Bytes(header), result));

	return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
