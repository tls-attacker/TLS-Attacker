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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PasswordSaltExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PasswordSaltExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PasswordSaltExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PasswordSaltExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC8492, used for the HelloRetryRequest */
@XmlRootElement(name = "PasswordSaltExtension")
public class PasswordSaltExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger saltLength;

    @ModifiableVariableProperty private ModifiableByteArray salt;

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

    @Override
    public PasswordSaltExtensionParser getParser(Context context, InputStream stream) {
        return new PasswordSaltExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public PasswordSaltExtensionPreparator getPreparator(Context context) {
        return new PasswordSaltExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public PasswordSaltExtensionSerializer getSerializer(Context context) {
        return new PasswordSaltExtensionSerializer(this);
    }

    @Override
    public PasswordSaltExtensionHandler getHandler(Context context) {
        return new PasswordSaltExtensionHandler(context.getTlsContext());
    }
}
