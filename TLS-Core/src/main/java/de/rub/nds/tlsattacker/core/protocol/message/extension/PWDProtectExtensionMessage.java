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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PWDProtectExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDProtectExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PWDProtectExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDProtectExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in RFC8492
 */
@XmlRootElement(name = "PWDProtectExtension")
public class PWDProtectExtensionMessage extends ExtensionMessage<PWDProtectExtensionMessage> {

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

    @Override
    public PWDProtectExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new PWDProtectExtensionParser(stream, tlsContext);
    }

    @Override
    public PWDProtectExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new PWDProtectExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public PWDProtectExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new PWDProtectExtensionSerializer(this);
    }

    @Override
    public PWDProtectExtensionHandler getHandler(TlsContext tlsContext) {
        return new PWDProtectExtensionHandler(tlsContext);
    }
}
