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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PWDClearExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDClearExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PWDClearExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDClearExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC8492 */
@XmlRootElement(name = "PWDClearExtension")
public class PWDClearExtensionMessage extends ExtensionMessage<PWDClearExtensionMessage> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger usernameLength;

    @ModifiableVariableProperty private ModifiableString username;

    public PWDClearExtensionMessage() {
        super(ExtensionType.PWD_CLEAR);
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

    public ModifiableString getUsername() {
        return username;
    }

    public void setUsername(String name) {
        this.username = ModifiableVariableFactory.safelySetValue(username, name);
    }

    public void setUsername(ModifiableString username) {
        this.username = username;
    }

    @Override
    public PWDClearExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new PWDClearExtensionParser(stream, tlsContext);
    }

    @Override
    public PWDClearExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new PWDClearExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public PWDClearExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new PWDClearExtensionSerializer(this);
    }

    @Override
    public PWDClearExtensionHandler getHandler(TlsContext tlsContext) {
        return new PWDClearExtensionHandler(tlsContext);
    }
}
