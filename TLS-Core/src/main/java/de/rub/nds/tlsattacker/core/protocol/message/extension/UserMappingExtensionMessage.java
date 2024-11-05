/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.UserMappingExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.UserMappingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.UserMappingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UserMappingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class UserMappingExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty private ModifiableByte userMappingType;

    public UserMappingExtensionMessage() {
        super(ExtensionType.USER_MAPPING);
    }

    public ModifiableByte getUserMappingType() {
        return userMappingType;
    }

    public void setUserMappingType(ModifiableByte userMappingType) {
        this.userMappingType = userMappingType;
    }

    public void setUserMappingType(byte userMappingType) {
        this.userMappingType =
                ModifiableVariableFactory.safelySetValue(this.userMappingType, userMappingType);
    }

    @Override
    public UserMappingExtensionParser getParser(Context context, InputStream stream) {
        return new UserMappingExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public UserMappingExtensionPreparator getPreparator(Context context) {
        return new UserMappingExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public UserMappingExtensionSerializer getSerializer(Context context) {
        return new UserMappingExtensionSerializer(this);
    }

    @Override
    public UserMappingExtensionHandler getHandler(Context context) {
        return new UserMappingExtensionHandler(context.getTlsContext());
    }
}
