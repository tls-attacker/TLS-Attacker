/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.protocol.heartbeat.handlers;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;

/**
 * Handler for Heartbeat messages: http://tools.ietf.org/html/rfc6520#page-4
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatHandler extends ProtocolMessageHandler<HeartbeatMessage> {

    /**
     * max payload length used in our application (not set by the spec)
     */
    static final int MAX_PAYLOAD_LENGTH = 256;

    /**
     * according to the specification, the min padding length is 16
     */
    static final int MIN_PADDING_LENGTH = 16;

    /**
     * max padding length used in our application (not set by the spec)
     */
    static final int MAX_PADDING_LENGTH = 256;

    private static HeartbeatHandler instance;

    public HeartbeatHandler(TlsContext tlsContext) {
	super(tlsContext);
	correctProtocolMessageClass = HeartbeatMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setHeartbeatMessageType(HeartbeatMessageType.HEARTBEAT_REQUEST.getValue());

	int payloadLength = RandomHelper.getRandom().nextInt(MAX_PAYLOAD_LENGTH);

	byte[] payload = new byte[payloadLength];
	RandomHelper.getRandom().nextBytes(payload);
	protocolMessage.setPayload(payload);

	protocolMessage.setPayloadLength(protocolMessage.getPayload().getValue().length);

	// we create only 16 bytes of 0x00 padding (for convenience)
	// int paddingLength = randomGenerator.nextInt(MAX_PADDING_LENGTH) +
	// MIN_PADDING_LENGTH;
	int paddingLength = MIN_PADDING_LENGTH;
	byte[] padding = new byte[paddingLength];
	// randomGenerator.nextBytes(padding);
	protocolMessage.setPadding(padding);

	byte[] type = { protocolMessage.getHeartbeatMessageType().getValue() };
	byte[] result = ArrayConverter.concatenate(type, ArrayConverter.intToBytes(protocolMessage.getPayloadLength()
		.getValue(), HeartbeatByteLength.PAYLOAD_LENGTH), protocolMessage.getPayload().getValue(),
		protocolMessage.getPadding().getValue());

	protocolMessage.setCompleteResultingMessage(result);

	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }

}
