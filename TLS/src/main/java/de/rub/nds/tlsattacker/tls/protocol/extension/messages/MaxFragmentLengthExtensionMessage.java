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
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.MaxFragmentLengthExtensionHandler;

/**
 * Maximum Fragment Length Extension described in rfc3546
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class MaxFragmentLengthExtensionMessage extends ExtensionMessage {

    private MaxFragmentLength maxFragmentLengthConfig;

    /**
     * Maximum fragment length value described in rfc3546
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray maxFragmentLength;

    public MaxFragmentLengthExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.MAX_FRAGMENT_LENGTH;
    }

    public MaxFragmentLength getMaxFragmentLengthConfig() {
	return maxFragmentLengthConfig;
    }

    public void setMaxFragmentLengthConfig(MaxFragmentLength maxFragmentLengthConfig) {
	this.maxFragmentLengthConfig = maxFragmentLengthConfig;
    }

    public ModifiableByteArray getMaxFragmentLength() {
	return maxFragmentLength;
    }

    public void setMaxFragmentLength(ModifiableByteArray maxFragmentLength) {
	this.maxFragmentLength = maxFragmentLength;
    }

    public void setMaxFragmentLength(byte[] maxFragmentLength) {
	this.maxFragmentLength = ModifiableVariableFactory.safelySetValue(this.maxFragmentLength, maxFragmentLength);
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return MaxFragmentLengthExtensionHandler.getInstance();
    }

}
