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
 * This extension is defined in RFC8492, used for the HelloRetryRequest
 */
public class PasswordSaltExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger saltLength;

    @ModifiableVariableProperty
    private ModifiableByteArray salt;

    public PasswordSaltExtensionMessage() {
        super(ExtensionType.PASSWORD_SALT);
    }

    public ModifiableInteger getSaltLength() {
        return saltLength;
    }

    public void setSaltLength(int length) {
        this.saltLength = ModifiableVariableFactory.safelySetValue(saltLength, length);
    }

    public void setSaltLength(ModifiableInteger length) {
        this.saltLength = length;
    }

    public ModifiableByteArray getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = ModifiableVariableFactory.safelySetValue(this.salt, salt);
    }

    public void setSalt(ModifiableByteArray salt) {
        this.salt = salt;
    }
}
