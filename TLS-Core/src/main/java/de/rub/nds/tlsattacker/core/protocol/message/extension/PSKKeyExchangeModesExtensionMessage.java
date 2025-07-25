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
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.PSKKeyExchangeModesExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PSKKeyExchangeModesExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PSKKeyExchangeModesExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKKeyExchangeModesExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;

/** RFC draft-ietf-tls-tls13-21 */
@XmlRootElement(name = "PSKKeyExchangeModesExtension")
@XmlAccessorType(XmlAccessType.FIELD)
public class PSKKeyExchangeModesExtensionMessage extends ExtensionMessage {

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] keyExchangeModesConfig;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger keyExchangeModesListLength;

    @ModifiableVariableProperty private ModifiableByteArray keyExchangeModesListBytes;

    public PSKKeyExchangeModesExtensionMessage() {
        super(ExtensionType.PSK_KEY_EXCHANGE_MODES);
    }

    public PSKKeyExchangeModesExtensionMessage(Config tlsConfig) {
        super(ExtensionType.PSK_KEY_EXCHANGE_MODES);
        int length = tlsConfig.getPSKKeyExchangeModes().size();
        byte[] listBytes = new byte[length];

        for (int x = 0; x < length; x++) {
            listBytes[x] = tlsConfig.getPSKKeyExchangeModes().get(x).getValue();
        }

        keyExchangeModesConfig = listBytes;
    }

    public ModifiableInteger getKeyExchangeModesListLength() {
        return keyExchangeModesListLength;
    }

    public void setKeyExchangeModesListLength(ModifiableInteger length) {
        this.keyExchangeModesListLength = length;
    }

    public void setKeyExchangeModesListLength(int length) {
        this.keyExchangeModesListLength =
                ModifiableVariableFactory.safelySetValue(keyExchangeModesListLength, length);
    }

    public ModifiableByteArray getKeyExchangeModesListBytes() {
        return keyExchangeModesListBytes;
    }

    public void setKeyExchangeModesListBytes(ModifiableByteArray keyExchangeModesListBytes) {
        this.keyExchangeModesListBytes = keyExchangeModesListBytes;
    }

    public void setKeyExchangeModesListBytes(byte[] bytes) {
        this.keyExchangeModesListBytes =
                ModifiableVariableFactory.safelySetValue(keyExchangeModesListBytes, bytes);
    }

    public byte[] getKeyExchangeModesConfig() {
        return keyExchangeModesConfig;
    }

    public void setKeyExchangeModesConfig(byte[] keyExchangeModesConfig) {
        this.keyExchangeModesConfig = keyExchangeModesConfig;
    }

    @Override
    public PSKKeyExchangeModesExtensionParser getParser(Context context, InputStream stream) {
        return new PSKKeyExchangeModesExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public PSKKeyExchangeModesExtensionPreparator getPreparator(Context context) {
        return new PSKKeyExchangeModesExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public PSKKeyExchangeModesExtensionSerializer getSerializer(Context context) {
        return new PSKKeyExchangeModesExtensionSerializer(this);
    }

    @Override
    public PSKKeyExchangeModesExtensionHandler getHandler(Context context) {
        return new PSKKeyExchangeModesExtensionHandler(context.getTlsContext());
    }
}
