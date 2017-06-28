/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.UserMappingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class UserMappingExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    ModifiableByte userMappingType;

    public UserMappingExtensionMessage() {
        super(ExtensionType.USER_MAPPING);
    }

    @Override
    public UserMappingExtensionHandler getHandler(TlsContext context) {
        return new UserMappingExtensionHandler(context);
    }

    public ModifiableByte getUserMappingType() {
        return userMappingType;
    }

    public void setUserMappingType(ModifiableByte userMappingType) {
        this.userMappingType = userMappingType;
    }

    public void setUserMappingType(byte userMappingType) {
        this.userMappingType = ModifiableVariableFactory.safelySetValue(this.userMappingType, userMappingType);
    }

}
