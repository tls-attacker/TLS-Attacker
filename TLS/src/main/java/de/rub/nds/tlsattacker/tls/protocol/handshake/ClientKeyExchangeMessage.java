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

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ClientKeyExchangeMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray masterSecret;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    ModifiableByteArray premasterSecret;

    public ClientKeyExchangeMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableByteArray getMasterSecret() {
	return masterSecret;
    }

    public void setMasterSecret(ModifiableByteArray masterSecret) {
	this.masterSecret = masterSecret;
    }

    public void setMasterSecret(byte[] value) {
	this.masterSecret = ModifiableVariableFactory.safelySetValue(this.masterSecret, value);
    }

    public ModifiableByteArray getPremasterSecret() {
	return premasterSecret;
    }

    public void setPremasterSecret(ModifiableByteArray premasterSecret) {
	this.premasterSecret = premasterSecret;
    }

    public void setPremasterSecret(byte[] premasterSecret) {
	this.premasterSecret = ModifiableVariableFactory.safelySetValue(this.premasterSecret, premasterSecret);
    }

}
