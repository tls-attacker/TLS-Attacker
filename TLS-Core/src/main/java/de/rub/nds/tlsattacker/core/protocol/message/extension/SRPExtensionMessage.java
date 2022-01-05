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
 * This extension is defined in RFC5054
 */
@XmlRootElement(name = "SRPExtension")
public class SRPExtensionMessage extends ExtensionMessage {

    // UTF-8 encoded and according to RFC 4013 with the SASLprep profile
    @ModifiableVariableProperty
    private ModifiableByteArray srpIdentifier;

    @ModifiableVariableProperty
    private ModifiableInteger srpIdentifierLength;

    public SRPExtensionMessage() {
        super(ExtensionType.SRP);
    }

    public SRPExtensionMessage(Config config) {
        super(ExtensionType.SRP);
    }

    public ModifiableByteArray getSrpIdentifier() {
        return srpIdentifier;
    }

    public void setSrpIdentifier(ModifiableByteArray srpIdentifier) {
        this.srpIdentifier = srpIdentifier;
    }

    public void setSrpIdentifier(byte[] srpIdentifier) {
        this.srpIdentifier = ModifiableVariableFactory.safelySetValue(this.srpIdentifier, srpIdentifier);
    }

    public ModifiableInteger getSrpIdentifierLength() {
        return srpIdentifierLength;
    }

    public void setSrpIdentifierLength(ModifiableInteger srpIdentifierLength) {
        this.srpIdentifierLength = srpIdentifierLength;
    }

    public void setSrpIdentifierLength(int srpIdentifierLength) {
        this.srpIdentifierLength =
            ModifiableVariableFactory.safelySetValue(this.srpIdentifierLength, srpIdentifierLength);
    }

}
