/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Florian Pfützenreuter
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
package de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;

/**
 * @author Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class HandshakeMessageFields {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length = ModifiableVariableFactory.createIntegerModifiableVariable();

    public ModifiableInteger getLength() {
	return length;
    }

    public void setLength(ModifiableInteger length) {
	this.length = length;
    }

    public void setLength(int length) {
	this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }
}