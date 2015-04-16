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
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EllipticCurvesExtensionMessage extends ExtensionMessage {

    private List<NamedCurve> supportedCurvesConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableVariable<Integer> supportedCurvesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableVariable<byte[]> supportedCurves;

    public EllipticCurvesExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.ELLIPTIC_CURVES;
    }

    public ModifiableVariable<Integer> getSupportedCurvesLength() {
	return supportedCurvesLength;
    }

    public void setSupportedCurvesLength(int length) {
	if (this.supportedCurvesLength == null) {
	    this.supportedCurvesLength = new ModifiableVariable<>();
	}
	this.supportedCurvesLength.setOriginalValue(length);
    }

    public ModifiableVariable<byte[]> getSupportedCurves() {
	return supportedCurves;
    }

    public void setSupportedCurves(byte[] array) {
	if (this.supportedCurves == null) {
	    this.supportedCurves = new ModifiableVariable<>();
	}
	supportedCurves.setOriginalValue(array);
    }

    public void setSupportedCurvesLength(ModifiableVariable<Integer> supportedCurvesLength) {
	this.supportedCurvesLength = supportedCurvesLength;
    }

    public void setSupportedCurves(ModifiableVariable<byte[]> supportedCurves) {
	if (this.supportedCurves == null) {
	    this.supportedCurves = new ModifiableVariable<>();
	}
	this.supportedCurves = supportedCurves;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return EllipticCurvesExtensionHandler.getInstance();
    }

    public List<NamedCurve> getSupportedCurvesConfig() {
	return supportedCurvesConfig;
    }

    public void setSupportedCurvesConfig(List<NamedCurve> supportedCurvesConfig) {
	this.supportedCurvesConfig = supportedCurvesConfig;
    }
}
