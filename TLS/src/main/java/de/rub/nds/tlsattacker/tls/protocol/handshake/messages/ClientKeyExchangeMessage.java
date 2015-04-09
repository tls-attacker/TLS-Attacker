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
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ClientKeyExchangeMessage extends HandshakeMessage {
    ModifiableVariable<byte[]> masterSecret;
    ModifiableVariable<byte[]> premasterSecret;

    public ClientKeyExchangeMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableVariable<byte[]> getMasterSecret() {
	return masterSecret;
    }

    public void setMasterSecret(byte[] value) {
	if (this.masterSecret == null) {
	    this.masterSecret = new ModifiableVariable<>();
	}
	this.masterSecret.setOriginalValue(value);
    }

    public ModifiableVariable<byte[]> getPremasterSecret() {
	return premasterSecret;
    }

    public void setPremasterSecret(ModifiableVariable<byte[]> premasterSecret) {
	this.premasterSecret = premasterSecret;
    }

    public void setPremasterSecret(byte[] premasterSecret) {
	if (this.premasterSecret == null) {
	    this.premasterSecret = new ModifiableVariable<>();
	}
	this.premasterSecret.setOriginalValue(premasterSecret);
    }

}
