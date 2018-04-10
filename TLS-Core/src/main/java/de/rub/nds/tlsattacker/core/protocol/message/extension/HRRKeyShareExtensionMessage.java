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

public class HRRKeyShareExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray selectedGroup;

    public HRRKeyShareExtensionMessage(ExtensionType type) {
        super(type);
        if (type != ExtensionType.KEY_SHARE && type != ExtensionType.KEY_SHARE_OLD) {
            throw new IllegalArgumentException("Only KeyShare types are allowed here. Found: " + type);
        }
    }

    public HRRKeyShareExtensionMessage() {
        super(ExtensionType.KEY_SHARE);
    }

    public ModifiableByteArray getSelectedGroup() {
        return selectedGroup;
    }

    public void setSelectedGroup(ModifiableByteArray selectedGroup) {
        this.selectedGroup = selectedGroup;
    }

    public void setSelectedGroup(byte[] bytes) {
        this.selectedGroup = ModifiableVariableFactory.safelySetValue(selectedGroup, bytes);
    }
}
