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

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
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
    ModifiableInteger supportedCurvesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray supportedCurves;

    public EllipticCurvesExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.ELLIPTIC_CURVES;
    }

    public ModifiableInteger getSupportedCurvesLength() {
	return supportedCurvesLength;
    }

    public void setSupportedCurvesLength(int length) {
	this.supportedCurvesLength = ModifiableVariableFactory.safelySetValue(supportedCurvesLength, length);
    }

    public ModifiableByteArray getSupportedCurves() {
	return supportedCurves;
    }

    public void setSupportedCurves(byte[] array) {
	supportedCurves = ModifiableVariableFactory.safelySetValue(supportedCurves, array);
    }

    public void setSupportedCurvesLength(ModifiableInteger supportedCurvesLength) {
	this.supportedCurvesLength = supportedCurvesLength;
    }

    public void setSupportedCurves(ModifiableByteArray supportedCurves) {
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
