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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.RenegotiationInfoExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * This extension is defined in RFC5746
 * 
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RenegotiationInfoExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray renegotiationInfo;

    public RenegotiationInfoExtensionMessage() {
        super(ExtensionType.RENEGOTIATION_INFO);
    }

    @Override
    public RenegotiationInfoExtensionHandler getHandler(TlsContext context) {
        return new RenegotiationInfoExtensionHandler(context);
    }

    public ModifiableByteArray getRenegotiationInfo() {
        return renegotiationInfo;
    }

    public void setRenegotiationInfo(ModifiableByteArray renegotiationInfo) {
        this.renegotiationInfo = renegotiationInfo;
    }

    public void setRenegotiationInfo(byte[] renegotiationInfo) {
        this.renegotiationInfo = ModifiableVariableFactory.safelySetValue(this.renegotiationInfo, renegotiationInfo);
    }

}
