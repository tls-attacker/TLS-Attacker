/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in RFC5746
 */
@XmlRootElement(name = "RenegotiationInfoExtension")
public class RenegotiationInfoExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray renegotiationInfo;

    @ModifiableVariableProperty
    private ModifiableInteger renegotiationInfoLength;

    public RenegotiationInfoExtensionMessage() {
        super(ExtensionType.RENEGOTIATION_INFO);
    }

    public RenegotiationInfoExtensionMessage(Config config) {
        super(ExtensionType.RENEGOTIATION_INFO);
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

    public ModifiableInteger getRenegotiationInfoLength() {
        return renegotiationInfoLength;
    }

    public void setRenegotiationInfoLength(ModifiableInteger renegotiationInfoLength) {
        this.renegotiationInfoLength = renegotiationInfoLength;
    }

    public void setRenegotiationInfoLength(int renegotiationInfoLength) {
        this.renegotiationInfoLength =
            ModifiableVariableFactory.safelySetValue(this.renegotiationInfoLength, renegotiationInfoLength);
    }
}
