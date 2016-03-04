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
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ServerHelloDoneHandler extends HandshakeMessageHandler<ServerHelloDoneMessage> {

    public ServerHelloDoneHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ServerHelloDoneMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {

	HandshakeMessageFields protocolMessageFields = protocolMessage.getMessageFields();

	protocolMessageFields.setLength(0);

	long header = (HandshakeMessageType.SERVER_HELLO_DONE.getValue() << 24)
		+ protocolMessageFields.getLength().getValue();

	protocolMessage.setCompleteResultingMessage(ArrayConverter.longToUint32Bytes(header));

	return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.SERVER_HELLO_DONE.getValue()) {
	    throw new InvalidMessageTypeException("This is not a Server Hello Done message");
	}
	HandshakeMessageFields protocolMessageFields = protocolMessage.getMessageFields();

	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessageFields.setLength(length);
	// should always be null

	currentPointer = nextPointer;

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	return currentPointer;
    }
}
