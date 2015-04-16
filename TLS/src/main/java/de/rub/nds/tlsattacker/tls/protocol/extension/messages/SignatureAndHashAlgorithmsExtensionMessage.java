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
package de.rub.nds.tlsattacker.tls.protocol.extension.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.SignatureAndHashAlgorithmsExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAndHashAlgorithm;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SignatureAndHashAlgorithmsExtensionMessage extends ExtensionMessage {

    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmsConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableVariable<Integer> signatureAndHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableVariable<byte[]> signatureAndHashAlgorithms;

    public SignatureAndHashAlgorithmsExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS;
    }

    public ModifiableVariable<Integer> getSignatureAndHashAlgorithmsLength() {
	return signatureAndHashAlgorithmsLength;
    }

    public void setSignatureAndHashAlgorithmsLength(int length) {
	this.signatureAndHashAlgorithmsLength = ModifiableVariableFactory.safelySetValue(
		this.signatureAndHashAlgorithmsLength, length);
    }

    public ModifiableVariable<byte[]> getSignatureAndHashAlgorithms() {
	return signatureAndHashAlgorithms;
    }

    public void setSignatureAndHashAlgorithms(byte[] array) {
	this.signatureAndHashAlgorithms = ModifiableVariableFactory.safelySetValue(this.signatureAndHashAlgorithms,
		array);
    }

    public void setSignatureAndHashAlgorithmsLength(ModifiableVariable<Integer> signatureAndHashAlgorithmsLength) {
	this.signatureAndHashAlgorithmsLength = signatureAndHashAlgorithmsLength;
    }

    public void setSignatureAndHashAlgorithms(ModifiableVariable<byte[]> signatureAndHashAlgorithms) {
	this.signatureAndHashAlgorithms = signatureAndHashAlgorithms;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return SignatureAndHashAlgorithmsExtensionHandler.getInstance();
    }

    public List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithmsConfig() {
	return signatureAndHashAlgorithmsConfig;
    }

    public void setSignatureAndHashAlgorithmsConfig(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmsConfig) {
	this.signatureAndHashAlgorithmsConfig = signatureAndHashAlgorithmsConfig;
    }
}
