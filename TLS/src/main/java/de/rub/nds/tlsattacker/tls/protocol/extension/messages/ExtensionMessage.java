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
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public abstract class ExtensionMessage extends ModifiableVariableHolder implements Serializable {

    ExtensionType extensionTypeConstant;

    ModifiableVariable<byte[]> extensionType;

    ModifiableVariable<Integer> extensionLength;

    ModifiableVariable<byte[]> extensionBytes;

    public ModifiableVariable<byte[]> getExtensionType() {
	return extensionType;
    }

    public ModifiableVariable<Integer> getExtensionLength() {
	return extensionLength;
    }

    public ModifiableVariable<byte[]> getExtensionBytes() {
	return extensionBytes;
    }

    public void setExtensionType(byte[] array) {
	if (this.extensionType == null) {
	    this.extensionType = new ModifiableVariable<>();
	}
	this.extensionType.setOriginalValue(array);
    }

    public void setExtensionLength(int length) {
	if (this.extensionLength == null) {
	    this.extensionLength = new ModifiableVariable<>();
	}
	this.extensionLength.setOriginalValue(length);
    }

    public void setExtensionBytes(byte[] data) {
	if (this.extensionBytes == null) {
	    this.extensionBytes = new ModifiableVariable<>();
	}
	this.extensionBytes.setOriginalValue(data);
    }

    public void setExtensionType(ModifiableVariable<byte[]> extensionType) {
	this.extensionType = extensionType;
    }

    public void setExtensionLength(ModifiableVariable<Integer> extensionLength) {
	this.extensionLength = extensionLength;
    }

    public void setExtensionBytes(ModifiableVariable<byte[]> extensionBytes) {
	this.extensionBytes = extensionBytes;
    }

    public ExtensionType getExtensionTypeConstant() {
	return extensionTypeConstant;
    }

    public abstract ExtensionHandler getExtensionHandler();

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\n    Extension type: ").append(ArrayConverter.bytesToHexString(extensionType.getValue()))
		.append("\n    Extension length: ").append(extensionLength.getValue());
	return sb.toString();
    }
}
