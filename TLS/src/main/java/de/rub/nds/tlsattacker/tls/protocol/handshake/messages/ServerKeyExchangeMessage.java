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
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerKeyExchangeMessage extends HandshakeMessage {
    /** hash algorithm */
    ModifiableVariable<Byte> hashAlgorithm;
    /** signature algorithm */
    ModifiableVariable<Byte> signatureAlgorithm;
    /** signature length */
    ModifiableVariable<Integer> signatureLength;
    /** signature */
    ModifiableVariable<byte[]> signature;

    public ServerKeyExchangeMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableVariable<Byte> getHashAlgorithm() {
	return hashAlgorithm;
    }

    public void setHashAlgorithm(ModifiableVariable<Byte> hashAlgorithm) {
	this.hashAlgorithm = hashAlgorithm;
    }

    public void setHashAlgorithm(byte algorithm) {
	this.hashAlgorithm = ModifiableVariableFactory.safelySetValue(this.hashAlgorithm, algorithm);
    }

    public ModifiableVariable<Byte> getSignatureAlgorithm() {
	return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(ModifiableVariable<Byte> signatureAlgorithm) {
	this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setSignatureAlgorithm(byte algorithm) {
	this.signatureAlgorithm = ModifiableVariableFactory.safelySetValue(this.signatureAlgorithm, algorithm);
    }

    public ModifiableVariable<Integer> getSignatureLength() {
	return signatureLength;
    }

    public void setSignatureLength(ModifiableVariable<Integer> signatureLength) {
	this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int length) {
	this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, length);
    }

    public ModifiableVariable<byte[]> getSignature() {
	return signature;
    }

    public void setSignature(ModifiableVariable<byte[]> signature) {
	this.signature = signature;
    }

    public void setSignature(byte[] signature) {
	this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

}
