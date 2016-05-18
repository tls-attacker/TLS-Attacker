/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
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
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class HandshakeMessage extends ProtocolMessage {

    final HandshakeMessageType handshakeMessageType;

    /**
     * handshake type
     */
    @ModifiableVariableProperty
    ModifiableByte type;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    protected ModifiableInteger length = ModifiableVariableFactory.createIntegerModifiableVariable();

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger messageSeq;

    @ModifiableVariableProperty
    private ModifiableInteger fragmentOffset;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger fragmentLength;

    boolean includeInDigest = true;

    public HandshakeMessage(HandshakeMessageType handshakeMessageType) {
	this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
	this.handshakeMessageType = handshakeMessageType;

	this.messageSeq = ModifiableVariableFactory.safelySetValue(messageSeq, 0);
	this.fragmentOffset = ModifiableVariableFactory.safelySetValue(fragmentOffset, 0);
	this.fragmentLength = ModifiableVariableFactory.safelySetValue(fragmentLength, 0);
    }

    public ModifiableByte getType() {
	return type;
    }

    public boolean getIncludeInDigest() {
	return includeInDigest;
    }

    public void setType(ModifiableByte type) {
	this.type = type;
    }

    public void setType(Byte type) {
	this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public ModifiableInteger getLength() {
	return length;
    }

    public void setLength(ModifiableInteger length) {
	this.length = length;
    }

    public void setLength(int length) {
	this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableInteger getMessageSeq() {
	return messageSeq;
    }

    public ModifiableInteger getFragmentOffset() {
	return fragmentOffset;
    }

    public ModifiableInteger getFragmentLength() {
	return fragmentLength;
    }

    public void setMessageSeq(int messageSeq) {
	this.messageSeq = ModifiableVariableFactory.safelySetValue(this.messageSeq, messageSeq);
    }

    public void setMessageSeq(ModifiableInteger messageSeq) {
	this.messageSeq = messageSeq;
    }

    public void setFragmentOffset(int fragmentOffset) {
	this.fragmentOffset = ModifiableVariableFactory.safelySetValue(this.fragmentOffset, fragmentOffset);
    }

    public void setFragmentOffset(ModifiableInteger fragmentOffset) {
	this.fragmentOffset = fragmentOffset;
    }

    public void setFragmentLength(int fragmentLength) {
	this.fragmentLength = ModifiableVariableFactory.safelySetValue(this.fragmentLength, fragmentLength);
    }

    public void setFragmentLength(ModifiableInteger fragmentLength) {
	this.fragmentLength = fragmentLength;
    }

    public HandshakeMessageType getHandshakeMessageType() {
	return handshakeMessageType;
    }

    public void setIncludeInDigest(boolean includeInDigest) {
	this.includeInDigest = includeInDigest;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder("\n" + handshakeMessageType.getName());
	sb.append("\n  Handshake Message Length: ").append(length.getValue());
	if (messageSeq != null && messageSeq.getValue() != null && messageSeq.getValue() != 0) {
	    sb.append("\n  Handshake Message message_seq: ").append(messageSeq.getValue());
	    sb.append("\n  Handshake Message fragment_offset: ").append(fragmentOffset.getValue());
	    sb.append("\n  Handshake Message fragment_length: ").append(fragmentLength.getValue());
	}
	return sb.toString();
    }

    @Override
    public String toCompactString() {
	return handshakeMessageType.getName();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	ProtocolMessageHandler pmh = handshakeMessageType.getProtocolMessageHandler(tlsContext);
	pmh.setProtocolMessage(this);
	return pmh;
    }
}
