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
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RSAClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    ModifiableVariable<Integer> encryptedPremasterSecretLength;

    ModifiableVariable<byte[]> encryptedPremasterSecret;

    ModifiableVariable<byte[]> plainPaddedPremasterSecret;

    public RSAClientKeyExchangeMessage() {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public RSAClientKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<Integer> getEncryptedPremasterSecretLength() {
	return encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(ModifiableVariable<Integer> encryptedPremasterSecretLength) {
	this.encryptedPremasterSecretLength = encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(int length) {
	if (this.encryptedPremasterSecretLength == null) {
	    this.encryptedPremasterSecretLength = new ModifiableVariable<>();
	}
	this.encryptedPremasterSecretLength.setOriginalValue(length);
    }

    public ModifiableVariable<byte[]> getEncryptedPremasterSecret() {
	return encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(ModifiableVariable<byte[]> encryptedPremasterSecret) {
	this.encryptedPremasterSecret = encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(byte[] value) {
	if (this.encryptedPremasterSecret == null) {
	    this.encryptedPremasterSecret = new ModifiableVariable<>();
	}
	this.encryptedPremasterSecret.setOriginalValue(value);
    }

    public ModifiableVariable<byte[]> getPlainPaddedPremasterSecret() {
	return plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(ModifiableVariable<byte[]> plainPaddedPremasterSecret) {
	this.plainPaddedPremasterSecret = plainPaddedPremasterSecret;
    }

    public void setPlainPaddedPremasterSecret(byte[] value) {
	if (this.plainPaddedPremasterSecret == null) {
	    this.plainPaddedPremasterSecret = new ModifiableVariable<>();
	}
	this.plainPaddedPremasterSecret.setOriginalValue(value);
    }

    public void setMasterSecret(ModifiableVariable<byte[]> masterSecret) {
	this.masterSecret = masterSecret;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nClient Key Exchange message:");
	return sb.toString();
    }
}
