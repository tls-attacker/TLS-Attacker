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
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class FinishedMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    ModifiableVariable<byte[]> verifyData;

    public FinishedMessage() {
	super(HandshakeMessageType.FINISHED);
    }

    public FinishedMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.FINISHED);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<byte[]> getVerifyData() {
	return verifyData;
    }

    public void setVerifyData(ModifiableVariable<byte[]> verifyData) {
	this.verifyData = verifyData;
    }

    public void setVerifyData(byte[] value) {
	if (this.verifyData == null) {
	    this.verifyData = new ModifiableVariable<>();
	}
	this.verifyData.setOriginalValue(value);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nFinished message:").append(super.toString()).append("\n  Verify Data: ")
		.append(ArrayConverter.bytesToHexString(verifyData.getValue()));
	return sb.toString();
    }
}
