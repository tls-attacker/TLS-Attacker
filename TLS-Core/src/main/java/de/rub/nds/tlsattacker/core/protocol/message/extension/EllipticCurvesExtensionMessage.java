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
 * This extension is defined in RFC-ietf-tls-rfc4492bis-17 Also known as "supported_groups" extension
 */
@XmlRootElement(name = "EllipticCurves")
public class EllipticCurvesExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supportedGroupsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedGroups;

    public EllipticCurvesExtensionMessage() {
        super(ExtensionType.ELLIPTIC_CURVES);
    }

    public EllipticCurvesExtensionMessage(Config config) {
        super(ExtensionType.ELLIPTIC_CURVES);
    }

    public ModifiableInteger getSupportedGroupsLength() {
        return supportedGroupsLength;
    }

    public void setSupportedGroupsLength(int length) {
        this.supportedGroupsLength = ModifiableVariableFactory.safelySetValue(supportedGroupsLength, length);
    }

    public void setSupportedGroupsLength(ModifiableInteger supportedGroupsLength) {
        this.supportedGroupsLength = supportedGroupsLength;
    }

    public ModifiableByteArray getSupportedGroups() {
        return supportedGroups;
    }

    public void setSupportedGroups(byte[] array) {
        supportedGroups = ModifiableVariableFactory.safelySetValue(supportedGroups, array);
    }

    public void setSupportedGroups(ModifiableByteArray supportedGroups) {
        this.supportedGroups = supportedGroups;
    }
}
