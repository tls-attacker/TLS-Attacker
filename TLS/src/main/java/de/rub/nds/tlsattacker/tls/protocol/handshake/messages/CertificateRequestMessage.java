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
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateRequestMessage extends HandshakeMessage {

    ModifiableVariable<Integer> clientCertificateTypesCount;

    ModifiableVariable<byte[]> clientCertificateTypes;

    ModifiableVariable<Integer> signatureHashAlgorithmsLength;

    ModifiableVariable<byte[]> signatureHashAlgorithms;

    ModifiableVariable<Integer> distinguishedNamesLength;

    ModifiableVariable<byte[]> distinguishedNames;

    public CertificateRequestMessage() {
	super(HandshakeMessageType.CERTIFICATE_REQUEST);
	this.messageIssuer = ConnectionEnd.SERVER;
    }

    public CertificateRequestMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.CERTIFICATE_REQUEST);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<Integer> getClientCertificateTypesCount() {
	return clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(ModifiableVariable<Integer> clientCertificateTypesCount) {
	this.clientCertificateTypesCount = clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(int clientCertificateTypesCount) {
	this.clientCertificateTypesCount = ModifiableVariableFactory.safelySetValue(this.clientCertificateTypesCount,
		clientCertificateTypesCount);
    }

    public ModifiableVariable<byte[]> getClientCertificateTypes() {
	return clientCertificateTypes;
    }

    public void setClientCertificateTypes(ModifiableVariable<byte[]> clientCertificateTypes) {
	this.clientCertificateTypes = clientCertificateTypes;
    }

    public void setClientCertificateTypes(byte[] clientCertificateTypes) {
	this.clientCertificateTypes = ModifiableVariableFactory.safelySetValue(this.clientCertificateTypes,
		clientCertificateTypes);
    }

    public ModifiableVariable<Integer> getSignatureHashAlgorithmsLength() {
	return signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(ModifiableVariable<Integer> signatureHashAlgorithmsLength) {
	this.signatureHashAlgorithmsLength = signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(int signatureHashAlgorithmsLength) {
	this.signatureHashAlgorithmsLength = ModifiableVariableFactory.safelySetValue(
		this.signatureHashAlgorithmsLength, signatureHashAlgorithmsLength);
    }

    public ModifiableVariable<byte[]> getSignatureHashAlgorithms() {
	return signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(ModifiableVariable<byte[]> signatureHashAlgorithms) {
	this.signatureHashAlgorithms = signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(byte[] signatureHashAlgorithms) {
	this.signatureHashAlgorithms = ModifiableVariableFactory.safelySetValue(this.signatureHashAlgorithms,
		signatureHashAlgorithms);
    }

    public ModifiableVariable<Integer> getDistinguishedNamesLength() {
	return distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(ModifiableVariable<Integer> distinguishedNamesLength) {
	this.distinguishedNamesLength = distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(int distinguishedNamesLength) {
	this.distinguishedNamesLength = ModifiableVariableFactory.safelySetValue(this.distinguishedNamesLength,
		distinguishedNamesLength);
    }

    public ModifiableVariable<byte[]> getDistinguishedNames() {
	return distinguishedNames;
    }

    public void setDistinguishedNames(ModifiableVariable<byte[]> distinguishedNames) {
	this.distinguishedNames = distinguishedNames;
    }

    public void setDistinguishedNames(byte[] distinguishedNames) {
	this.distinguishedNames = ModifiableVariableFactory.safelySetValue(this.distinguishedNames, distinguishedNames);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder(super.toString());
	sb.append("\n  Certificate Types Count: ").append(clientCertificateTypesCount.getValue());
	sb.append("\n  Certificate Types: ");
	for (int i = 0; i < clientCertificateTypesCount.getValue(); i++) {
	    sb.append(ClientCertificateType.getClientCertificateType(clientCertificateTypes.getValue()[i]))
		    .append(", ");
	}
	sb.append("\n  Signature Hash Algorithms Length: ").append(signatureHashAlgorithmsLength.getValue());
	sb.append("\n  Signature Hash Algorithms: ");
	for (int i = 0; i < signatureHashAlgorithmsLength.getValue(); i = i + 2) {
	    sb.append(HashAlgorithm.getHashAlgorithm(signatureHashAlgorithms.getValue()[i])).append("-");
	    sb.append(SignatureAlgorithm.getSignatureAlgorithm(signatureHashAlgorithms.getValue()[i + 1])).append(", ");
	}
	sb.append("\n  Distinguished Names Length: ").append(distinguishedNamesLength.getValue());
	sb.append("\n  Distinguished Names: ").append(ArrayConverter.bytesToHexString(distinguishedNames.getValue()));
	return sb.toString();
    }

}
