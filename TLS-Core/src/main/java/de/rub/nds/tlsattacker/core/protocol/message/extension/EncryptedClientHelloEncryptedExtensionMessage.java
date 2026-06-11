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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedClientHelloEncryptedExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.EncryptedClientHelloEncryptedExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EncryptedClientHelloEncryptedExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedClientHelloEncryptedExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

/** The encrypted client hello extension sent by the server to advertise ECH retry configurations */
@XmlRootElement(name = "EncryptedClientHelloEncryptedExtension")
public class EncryptedClientHelloEncryptedExtensionMessage extends ExtensionMessage {

    /** length of the echConfigs length field indicating the total lengths of all echConfigs */
    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger echConfigsLength;

    List<EchConfig> echConfigs = new LinkedList<>();

    public EncryptedClientHelloEncryptedExtensionMessage() {
        super(ExtensionType.ENCRYPTED_CLIENT_HELLO_ENCRYPTED_EXTENSIONS);
    }

    @Override
    public EncryptedClientHelloEncryptedExtensionParser getParser(
            Context context, InputStream stream) {
        return new EncryptedClientHelloEncryptedExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public EncryptedClientHelloEncryptedExtensionPreparator getPreparator(Context context) {
        return new EncryptedClientHelloEncryptedExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public EncryptedClientHelloEncryptedExtensionSerializer getSerializer(Context context) {
        return new EncryptedClientHelloEncryptedExtensionSerializer(this);
    }

    @Override
    public ExtensionHandler<EncryptedClientHelloEncryptedExtensionMessage> getHandler(
            Context context) {
        return new EncryptedClientHelloEncryptedExtensionHandler(context.getTlsContext());
    }

    public List<EchConfig> getEchConfigs() {
        return echConfigs;
    }

    public void setEchConfigs(List<EchConfig> echConfigs) {
        this.echConfigs = echConfigs;
    }

    public ModifiableInteger getEchConfigsLength() {
        return echConfigsLength;
    }

    public void setEchConfigsLength(int echConfigsLength) {
        this.echConfigsLength =
                ModifiableVariableFactory.safelySetValue(this.echConfigsLength, echConfigsLength);
    }
}
