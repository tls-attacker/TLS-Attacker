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
 * This extension is defined in RFC8492
 */
public class PWDProtectExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger usernameLength;

    @ModifiableVariableProperty
    private ModifiableByteArray username;

    public PWDProtectExtensionMessage() {
        super(ExtensionType.PWD_PROTECT);
    }

    public ModifiableInteger getUsernameLength() {
        return usernameLength;
    }

    public void setUsernameLength(int length) {
        this.usernameLength = ModifiableVariableFactory.safelySetValue(usernameLength, length);
    }

    public void setUsernameLength(ModifiableInteger usernameLength) {
        this.usernameLength = usernameLength;
    }

    public ModifiableByteArray getUsername() {
        return username;
    }

    public void setUsername(byte[] name) {
        this.username = ModifiableVariableFactory.safelySetValue(username, name);
    }

    public void setUsername(ModifiableByteArray username) {
        this.username = username;
    }
}
