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
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.ECCurveType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableVariable<Byte> curveType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableVariable<byte[]> namedCurve;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableVariable<Integer> publicKeyLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableVariable<byte[]> publicKey;

    public ECDHEServerKeyExchangeMessage() {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public ECDHEServerKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<Byte> getCurveType() {
	return curveType;
    }

    public void setCurveType(ModifiableVariable<Byte> curveType) {
	this.curveType = curveType;
    }

    public void setCurveType(byte curveType) {
	this.curveType = ModifiableVariableFactory.safelySetValue(this.curveType, curveType);
    }

    public ModifiableVariable<byte[]> getNamedCurve() {
	return namedCurve;
    }

    public void setNamedCurve(ModifiableVariable<byte[]> namedCurve) {
	this.namedCurve = namedCurve;
    }

    public void setNamedCurve(byte[] namedCurve) {
	this.namedCurve = ModifiableVariableFactory.safelySetValue(this.namedCurve, namedCurve);
    }

    public ModifiableVariable<Integer> getPublicKeyLength() {
	return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableVariable<Integer> publicKeyLength) {
	this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int length) {
	this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, length);
    }

    public ModifiableVariable<byte[]> getPublicKey() {
	return publicKey;
    }

    public void setPublicKey(ModifiableVariable<byte[]> publicKey) {
	this.publicKey = publicKey;
    }

    public void setPublicKey(byte[] pubKey) {
	this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, pubKey);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n  Curve Type: ")
		.append(ECCurveType.getCurveType(this.curveType.getValue())).append("\n  Named Curve: ")
		.append(NamedCurve.getNamedCurve(this.namedCurve.getValue())).append("\n  Public Key: ")
		.append(ArrayConverter.bytesToHexString(this.publicKey.getValue())).append("\n  Signature Algorithm: ")
		.append(HashAlgorithm.getHashAlgorithm(this.hashAlgorithm.getValue())).append(" ")
		.append(SignatureAlgorithm.getSignatureAlgorithm(this.signatureAlgorithm.getValue()))
		.append("\n  Signature: ").append(ArrayConverter.bytesToHexString(this.signature.getValue()));

	return sb.toString();
    }
}
