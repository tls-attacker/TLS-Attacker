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
package de.rub.nds.tlsattacker.tls.protocol.ccs.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.ccs.handlers.ChangeCipherSpecHandler;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ChangeCipherSpecMessage extends ProtocolMessage {

    @ModifiableVariableProperty
    ModifiableByte ccsProtocolType;

    public ChangeCipherSpecMessage() {
	this.protocolMessageType = ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    public ChangeCipherSpecMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByte getCcsProtocolType() {
	return ccsProtocolType;
    }

    public void setCcsProtocolType(ModifiableByte ccsProtocolType) {
	this.ccsProtocolType = ccsProtocolType;
    }

    public void setCcsProtocolType(byte value) {
	this.ccsProtocolType = ModifiableVariableFactory.safelySetValue(ccsProtocolType, value);
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	ChangeCipherSpecHandler ccsh = new ChangeCipherSpecHandler(tlsContext);
	ccsh.setProtocolMessage(this);
	return ccsh;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nChangeCipherSpec message:").append("\n  CCS Protocol Message: ")
		.append(String.format("%02X ", ccsProtocolType.getValue()));
	return sb.toString();
    }
}
