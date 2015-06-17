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

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateVerifyMessage extends HandshakeMessage {

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

    public CertificateVerifyMessage() {
	super(HandshakeMessageType.CERTIFICATE_VERIFY);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public CertificateVerifyMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CERTIFICATE_VERIFY);
	this.messageIssuer = messageIssuer;
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
