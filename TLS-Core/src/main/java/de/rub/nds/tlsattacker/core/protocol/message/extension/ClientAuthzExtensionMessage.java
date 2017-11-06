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
 * This extension is defined in RFC5878
 */
public class ClientAuthzExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    ModifiableInteger authzFormatListLength;
    @ModifiableVariableProperty
    ModifiableByteArray authzFormatList;

    public ClientAuthzExtensionMessage() {
        super(ExtensionType.CLIENT_AUTHZ);
    }

    public ModifiableInteger getAuthzFormatListLength() {
        return authzFormatListLength;
    }

    public void setAuthzFormatListLength(ModifiableInteger authzFormatListLength) {
        this.authzFormatListLength = authzFormatListLength;
    }

    public void setAuthzFormatListLength(int authzFormatListLength) {
        this.authzFormatListLength = ModifiableVariableFactory.safelySetValue(this.authzFormatListLength,
                authzFormatListLength);
    }

    public ModifiableByteArray getAuthzFormatList() {
        return authzFormatList;
    }

    public void setAuthzFormatList(ModifiableByteArray authzFormatList) {
        this.authzFormatList = authzFormatList;
    }

    public void setAuthzFormatList(byte[] authzFormatList) {
        this.authzFormatList = ModifiableVariableFactory.safelySetValue(this.authzFormatList, authzFormatList);
    }

}
