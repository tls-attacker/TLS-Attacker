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
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerKeyExchangeMessage extends HandshakeMessage {

    /**
     * hash algorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte hashAlgorithm;
    /**
     * signature algorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte signatureAlgorithm;
    /**
     * signature length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger signatureLength;
    /**
     * signature
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.SIGNATURE)
    ModifiableByteArray signature;

    public ServerKeyExchangeMessage(HandshakeMessageType handshakeMessageType) {
	super(handshakeMessageType);
    }

    public ModifiableVariable<Byte> getHashAlgorithm() {
	return hashAlgorithm;
    }

    public void setHashAlgorithm(ModifiableByte hashAlgorithm) {
	this.hashAlgorithm = hashAlgorithm;
    }

    public void setHashAlgorithm(byte algorithm) {
	this.hashAlgorithm = ModifiableVariableFactory.safelySetValue(this.hashAlgorithm, algorithm);
    }

    public ModifiableVariable<Byte> getSignatureAlgorithm() {
	return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(ModifiableByte signatureAlgorithm) {
	this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setSignatureAlgorithm(byte algorithm) {
	this.signatureAlgorithm = ModifiableVariableFactory.safelySetValue(this.signatureAlgorithm, algorithm);
    }

    public ModifiableInteger getSignatureLength() {
	return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
	this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int length) {
	this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, length);
    }

    public ModifiableByteArray getSignature() {
	return signature;
    }

    public void setSignature(ModifiableByteArray signature) {
	this.signature = signature;
    }

    public void setSignature(byte[] signature) {
	this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

}
