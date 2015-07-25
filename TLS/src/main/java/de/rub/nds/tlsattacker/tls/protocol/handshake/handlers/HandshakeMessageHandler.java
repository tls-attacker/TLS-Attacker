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

import de.rub.nds.tlsattacker.dtls.protocol.handshake.messagefields.HandshakeMessageDtlsFields;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @param <ProtocolMessage>
 */
public abstract class HandshakeMessageHandler<ProtocolMessage extends HandshakeMessage> extends
	ProtocolMessageHandler<ProtocolMessage> {

    private byte[] dtlsAllMessageBytes;

    public HandshakeMessageHandler(TlsContext tlsContext) {
	super(tlsContext);
    }

    @Override
    protected byte[] beforeParseMessageAction(byte[] message, int pointer) {
	if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12) {
	    return prepareDtlsHandshakeMessageParse(message, pointer);
	}
	return message;
    }

    /**
     * Implementation hook used after the prepareMessageAction: the content of
     * the parsed protocol message is parsed and the digest value is updated
     * 
     * @param messageBytes
     * @return
     */
    @Override
    protected byte[] afterPrepareMessageAction(byte[] messageBytes) {
	if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12) {
	    protocolMessage.setCompleteResultingMessage(finishDtlsHandshakeMessagePrepare(messageBytes));
	}
	byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
	tlsContext.getDigest().update(pm);
	return pm;
    }

    /**
     * Implementation hook used after the parseMessageAction: the content of the
     * parsed protocol message is parsed and the digest value is updated
     * 
     * @param ret
     * @return
     */
    @Override
    protected int afterParseMessageAction(int ret) {
	if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12) {
	    protocolMessage.setCompleteResultingMessage(dtlsAllMessageBytes);
	    ret += 8;
	}
	byte[] pm = protocolMessage.getCompleteResultingMessage().getValue();
	tlsContext.getDigest().update(pm);
	return ret;
    }

    private byte[] prepareDtlsHandshakeMessageParse(byte[] message, int pointer) {
	dtlsAllMessageBytes = message;
	HandshakeMessageDtlsFields messageFields = new HandshakeMessageDtlsFields();
	byte[] parsePmBytes;

	messageFields.setMessageSeq((message[pointer + 4] << 8) + (message[pointer + 5] & 0xFF));
	messageFields.setFragmentOffset((message[pointer + 6] << 16) + (message[pointer + 7] << 8)
		+ (message[pointer + 8] & 0xFF));
	messageFields.setFragmentLength((message[pointer + 9] << 16) + (message[pointer + 10] << 8)
		+ (message[pointer + 11] & 0xFF));
	protocolMessage.setMessageFields(messageFields);

	parsePmBytes = new byte[message.length - 8];
	System.arraycopy(message, 0, parsePmBytes, 0, pointer);
	System.arraycopy(message, pointer, parsePmBytes, pointer, 4);
	System.arraycopy(message, pointer + 12, parsePmBytes, pointer + 4, message.length - pointer - 12);

	return parsePmBytes;
    }

    private byte[] finishDtlsHandshakeMessagePrepare(byte[] messageBytes) {
	HandshakeMessageDtlsFields messageFields = (HandshakeMessageDtlsFields) protocolMessage.getMessageFields();

	messageFields.setFragmentLength(messageBytes.length - 4);
	byte[] preparePmBytes = new byte[messageBytes.length + 8];

	System.arraycopy(messageBytes, 0, preparePmBytes, 0, 4);
	System.arraycopy(ArrayConverter.intToBytes(messageFields.getMessageSeq().getValue(), 2), 0, preparePmBytes, 4,
		2);
	System.arraycopy(ArrayConverter.intToBytes(messageFields.getFragmentOffset().getValue(), 3), 0, preparePmBytes,
		6, 3);
	System.arraycopy(ArrayConverter.intToBytes(messageFields.getFragmentLength().getValue(), 3), 0, preparePmBytes,
		9, 3);
	System.arraycopy(messageBytes, 4, preparePmBytes, 12, messageBytes.length - 4);

	return preparePmBytes;
    }

}
