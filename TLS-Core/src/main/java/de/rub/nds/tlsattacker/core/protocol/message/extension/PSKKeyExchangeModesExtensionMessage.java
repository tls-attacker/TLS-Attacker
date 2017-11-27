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
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * RFC draft-ietf-tls-tls13-21
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class PSKKeyExchangeModesExtensionMessage extends ExtensionMessage {

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
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
