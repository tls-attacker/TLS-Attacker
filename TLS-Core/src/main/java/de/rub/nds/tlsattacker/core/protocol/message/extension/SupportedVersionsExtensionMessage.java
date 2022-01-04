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

@XmlRootElement(name = "SupportedVersions")
public class SupportedVersionsExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger supportedVersionsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedVersions;

    public SupportedVersionsExtensionMessage() {
        super(ExtensionType.SUPPORTED_VERSIONS);
    }

    public SupportedVersionsExtensionMessage(Config config) {
        super(ExtensionType.SUPPORTED_VERSIONS);
    }

    public ModifiableInteger getSupportedVersionsLength() {
        return supportedVersionsLength;
    }

    public void setSupportedVersionsLength(int length) {
        this.supportedVersionsLength = ModifiableVariableFactory.safelySetValue(this.supportedVersionsLength, length);
    }

    public void setSupportedVersionsLength(ModifiableInteger supportedVersionsLength) {
        this.supportedVersionsLength = supportedVersionsLength;
    }

    public ModifiableByteArray getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(byte[] array) {
        this.supportedVersions = ModifiableVariableFactory.safelySetValue(this.supportedVersions, array);
    }

    public void setSupportedVersions(ModifiableByteArray supportedVersions) {
        this.supportedVersions = supportedVersions;
    }
}
