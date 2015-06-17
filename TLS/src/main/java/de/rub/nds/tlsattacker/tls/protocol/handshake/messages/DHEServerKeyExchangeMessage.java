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
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class DHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    /**
     * DH modulus length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger pLength;
    /**
     * DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger p;
    /**
     * DH generator length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger gLength;
    /**
     * DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger g;
    /**
     * public key length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger publicKeyLength;
    /**
     * public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    ModifiableBigInteger publicKey;

    public DHEServerKeyExchangeMessage() {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public DHEServerKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableInteger getpLength() {
	return pLength;
    }

    public void setpLength(ModifiableInteger pLength) {
	this.pLength = pLength;
    }

    public void setpLength(Integer pLength) {
	this.pLength = ModifiableVariableFactory.safelySetValue(this.pLength, pLength);
    }

    public ModifiableBigInteger getP() {
	return p;
    }

    public void setP(ModifiableBigInteger p) {
	this.p = p;
    }

    public void setP(BigInteger p) {
	this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableInteger getgLength() {
	return gLength;
    }

    public void setgLength(ModifiableInteger gLength) {
	this.gLength = gLength;
    }

    public void setgLength(Integer gLength) {
	this.gLength = ModifiableVariableFactory.safelySetValue(this.gLength, gLength);
    }

    public ModifiableBigInteger getG() {
	return g;
    }

    public void setG(ModifiableBigInteger g) {
	this.g = g;
    }

    public void setG(BigInteger g) {
	this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableBigInteger getPublicKey() {
	return publicKey;
    }

    public void setPublicKey(ModifiableBigInteger publicKey) {
	this.publicKey = publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
	this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
    }

    public ModifiableInteger getPublicKeyLength() {
	return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
	this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int length) {
	this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, length);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append(super.toString()).append("\n  Modulus p: ").append(p.getValue().toString(16))
		.append("\n  Generator g: ").append(g.getValue().toString(16)).append("\n  Public Key: ")
		.append(publicKey.getValue().toString(16)).append("\n  Signature Algorithm: ")
		.append(HashAlgorithm.getHashAlgorithm(this.hashAlgorithm.getValue())).append(" ")
		.append(SignatureAlgorithm.getSignatureAlgorithm(this.signatureAlgorithm.getValue()))
		.append("\n  Signature: ").append(ArrayConverter.bytesToHexString(this.signature.getValue()));

	return sb.toString();
    }
}
