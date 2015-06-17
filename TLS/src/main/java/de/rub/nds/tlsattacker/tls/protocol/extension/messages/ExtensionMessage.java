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
package de.rub.nds.tlsattacker.tls.protocol.extension.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
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

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray extensionType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger extensionLength;

    @ModifiableVariableProperty
    ModifiableByteArray extensionBytes;

    public ModifiableByteArray getExtensionType() {
	return extensionType;
    }

    public ModifiableInteger getExtensionLength() {
	return extensionLength;
    }

    public ModifiableByteArray getExtensionBytes() {
	return extensionBytes;
    }

    public void setExtensionType(byte[] array) {
	this.extensionType = ModifiableVariableFactory.safelySetValue(extensionType, array);
    }

    public void setExtensionLength(int length) {
	this.extensionLength = ModifiableVariableFactory.safelySetValue(extensionLength, length);
    }

    public void setExtensionBytes(byte[] data) {
	this.extensionBytes = ModifiableVariableFactory.safelySetValue(extensionBytes, data);
    }

    public void setExtensionType(ModifiableByteArray extensionType) {
	this.extensionType = extensionType;
    }

    public void setExtensionLength(ModifiableInteger extensionLength) {
	this.extensionLength = extensionLength;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
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
