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
 * This extension is defined in RFC5054
 */
public class SRPExtensionMessage extends ExtensionMessage {

    // UTF-8 encoed and according to RFC 4013 with the SASLprep profile
    @ModifiableVariableProperty
    private ModifiableByteArray srpIdentifier;

    @ModifiableVariableProperty
    private ModifiableInteger srpIdentifierLength;

    public SRPExtensionMessage() {
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
        this.srpIdentifierLength = ModifiableVariableFactory.safelySetValue(this.srpIdentifierLength,
                srpIdentifierLength);
    }

}
