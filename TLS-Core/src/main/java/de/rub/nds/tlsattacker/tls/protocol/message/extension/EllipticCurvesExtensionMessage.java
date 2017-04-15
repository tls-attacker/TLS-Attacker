/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
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

    @Override
    public EllipticCurvesExtensionHandler getHandler(TlsContext context) {
        return new EllipticCurvesExtensionHandler(context);
    }
}
