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
package de.rub.nds.tlsattacker.dtls.protocol.handshake.messagefields;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields.HandshakeMessageFields;

/**
 * Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class HandshakeMessageDtlsFields extends HandshakeMessageFields {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger messageSeq;

    @ModifiableVariableProperty
    private ModifiableInteger fragmentOffset;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger fragmentLength;

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

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\n  Handshake Message Length: ").append(length.getValue());
	sb.append("\n  Handshake Message message_seq: ").append(messageSeq.getValue());
	sb.append("\n  Handshake Message fragment_offset: ").append(fragmentOffset.getValue());
	sb.append("\n  Handshake Message fragment_length: ").append(fragmentLength.getValue());
	return sb.toString();
    }
}
