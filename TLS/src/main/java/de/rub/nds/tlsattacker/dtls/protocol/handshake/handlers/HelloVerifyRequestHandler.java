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
package de.rub.nds.tlsattacker.dtls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.protocol.handshake.handlers.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.messages.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields.HandshakeMessageFields;
import de.rub.nds.tlsattacker.tls.record.constants.ByteLength;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @param <HandshakeMessage>
 */
public class HelloVerifyRequestHandler<HandshakeMessage extends HelloVerifyRequestMessage> extends
	HandshakeMessageHandler<HandshakeMessage> {

    public HelloVerifyRequestHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = HelloVerifyRequestMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	byte[] content;
	HandshakeMessageFields messageFields = protocolMessage.getMessageFields();
	protocolMessage.setProtocolVersion(tlsContext.getProtocolVersion().getValue());

	// TODO: Calculate cookie via HMAC
	byte[] cookie = new byte[3];
	cookie[0] = (byte) 11;
	cookie[1] = (byte) 22;
	cookie[2] = (byte) 33;

	tlsContext.setDtlsHandshakeCookie(cookie);
	protocolMessage.setCookie(cookie);
	protocolMessage.setCookieLength((byte) cookie.length);

	content = ArrayConverter.concatenate(protocolMessage.getProtocolVersion().getValue(),
		new byte[] { protocolMessage.getCookieLength().getValue() }, protocolMessage.getCookie().getValue());

	messageFields.setLength(content.length);

	protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		new byte[] { HandshakeMessageType.HELLO_VERIFY_REQUEST.getValue() },
		ArrayConverter.intToBytes(messageFields.getLength().getValue(), 3), content));

	return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.HELLO_VERIFY_REQUEST.getValue()) {
	    throw new InvalidMessageTypeException("This is not a client verify message");
	}
	HandshakeMessageFields protocolMessageFields = protocolMessage.getMessageFields();

	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessageFields.setLength(length);

	currentPointer = nextPointer;
	nextPointer = currentPointer + ByteLength.PROTOCOL_VERSION;
	ProtocolVersion serverProtocolVersion = ProtocolVersion.getProtocolVersion(Arrays.copyOfRange(message,
		currentPointer, nextPointer));
	protocolMessage.setProtocolVersion(serverProtocolVersion.getValue());

	currentPointer = nextPointer;
	nextPointer += HandshakeByteLength.DTLS_HANDSHAKE_COOKIE_LENGTH;
	int cookieLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));

	byte[] cookie;
	currentPointer = nextPointer;
	nextPointer += cookieLength;
	cookie = Arrays.copyOfRange(message, currentPointer, nextPointer);
	protocolMessage.setCookie(cookie);
	protocolMessage.setCookieLength((byte) cookie.length);
	tlsContext.setDtlsHandshakeCookie(cookie);

	return nextPointer;
    }
}
