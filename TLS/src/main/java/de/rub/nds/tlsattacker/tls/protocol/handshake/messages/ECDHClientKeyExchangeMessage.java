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
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    /**
     * EC public key x coordinate
     */
    ModifiableVariable<BigInteger> publicKeyBaseX;
    /**
     * EC public key y coordinate
     */
    ModifiableVariable<BigInteger> publicKeyBaseY;
    /**
     * EC point format of the encoded EC point
     */
    ModifiableVariable<Byte> ecPointFormat;
    /**
     * Encoded EC point (without EC point format)
     */
    ModifiableVariable<byte[]> ecPointEncoded;
    /**
     * Supported EC point formats (can be used to trigger compression)
     */
    ModifiableVariable<byte[]> supportedPointFormats;
    /**
     * Length of the serialized public key
     */
    ModifiableVariable<Integer> publicKeyLength;

    public ECDHClientKeyExchangeMessage() {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = ConnectionEnd.CLIENT;
    }

    public ECDHClientKeyExchangeMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<BigInteger> getPublicKeyBaseX() {
	return publicKeyBaseX;
    }

    public void setPublicKeyBaseX(ModifiableVariable<BigInteger> publicKeyBaseX) {
	this.publicKeyBaseX = publicKeyBaseX;
    }

    public void setPublicKeyBaseX(BigInteger ecPointBaseX) {
	this.publicKeyBaseX = ModifiableVariableFactory.safelySetValue(this.publicKeyBaseX, ecPointBaseX);
    }

    public ModifiableVariable<BigInteger> getPublicKeyBaseY() {
	return publicKeyBaseY;
    }

    public void setPublicKeyBaseY(ModifiableVariable<BigInteger> publicKeyBaseY) {
	this.publicKeyBaseY = publicKeyBaseY;
    }

    public void setPublicKeyBaseY(BigInteger ecPointBaseY) {
	this.publicKeyBaseY = ModifiableVariableFactory.safelySetValue(this.publicKeyBaseY, ecPointBaseY);
    }

    public ModifiableVariable<Byte> getEcPointFormat() {
	return ecPointFormat;
    }

    public void setEcPointFormat(ModifiableVariable<Byte> ecPointFormat) {
	this.ecPointFormat = ecPointFormat;
    }

    public void setEcPointFormat(Byte ecPointFormat) {
	this.ecPointFormat = ModifiableVariableFactory.safelySetValue(this.ecPointFormat, ecPointFormat);
    }

    public ModifiableVariable<byte[]> getEcPointEncoded() {
	return ecPointEncoded;
    }

    public void setEcPointEncoded(ModifiableVariable<byte[]> ecPointEncoded) {
	this.ecPointEncoded = ecPointEncoded;
    }

    public void setEcPointEncoded(byte[] ecPointEncoded) {
	this.ecPointEncoded = ModifiableVariableFactory.safelySetValue(this.ecPointEncoded, ecPointEncoded);
    }

    public ModifiableVariable<byte[]> getSupportedPointFormats() {
	return supportedPointFormats;
    }

    public void setSupportedPointFormats(ModifiableVariable<byte[]> supportedPointFormats) {
	this.supportedPointFormats = supportedPointFormats;
    }

    public void setSupportedPointFormats(byte[] supportedPointFormats) {
	this.supportedPointFormats = ModifiableVariableFactory.safelySetValue(this.supportedPointFormats,
		supportedPointFormats);
    }

    public ModifiableVariable<Integer> getPublicKeyLength() {
	return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableVariable<Integer> publicKeyLength) {
	this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(Integer publicKeyLength) {
	this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder(super.toString());
	return sb.toString();
    }
}
