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
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * RFC draft-ietf-tls-tls13-21
 */
@XmlRootElement(name = "PSKKeyExchangeModesExtension")
@XmlAccessorType(XmlAccessType.FIELD)
public class PSKKeyExchangeModesExtensionMessage extends ExtensionMessage {

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] keyExchangeModesConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger keyExchangeModesListLength;

    @ModifiableVariableProperty
    private ModifiableByteArray keyExchangeModesListBytes;

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
        this.keyExchangeModesListLength = ModifiableVariableFactory.safelySetValue(keyExchangeModesListLength, length);
    }

    public ModifiableByteArray getKeyExchangeModesListBytes() {
        return keyExchangeModesListBytes;
    }

    public void setKeyExchangeModesListBytes(ModifiableByteArray keyExchangeModesListBytes) {
        this.keyExchangeModesListBytes = keyExchangeModesListBytes;
    }

    public void setKeyExchangeModesListBytes(byte[] bytes) {
        this.keyExchangeModesListBytes = ModifiableVariableFactory.safelySetValue(keyExchangeModesListBytes, bytes);
    }

    public byte[] getKeyExchangeModesConfig() {
        return keyExchangeModesConfig;
    }

    public void setKeyExchangeModesConfig(byte[] keyExchangeModesConfig) {
        this.keyExchangeModesConfig = keyExchangeModesConfig;
    }
}
