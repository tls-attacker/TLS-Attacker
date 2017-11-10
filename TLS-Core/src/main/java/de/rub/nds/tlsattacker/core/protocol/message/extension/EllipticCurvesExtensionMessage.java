/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

/**
 * This extension is defined in RFC-ietf-tls-rfc4492bis-17 Also known as
 * "supported_groups" extension
 */
public class EllipticCurvesExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supportedCurvesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedCurves;

    public EllipticCurvesExtensionMessage() {
        super(ExtensionType.ELLIPTIC_CURVES);
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
}
