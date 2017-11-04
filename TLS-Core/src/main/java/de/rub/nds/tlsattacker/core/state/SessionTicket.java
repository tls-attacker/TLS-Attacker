/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;

/**
 *
 * @author Timon Wern <timon.wern@rub.de>
 */
public class SessionTicket extends ModifiableVariableHolder implements Serializable {
    @ModifiableVariableProperty()
    private ModifiableByteArray keyName; // 16 Byte

    @ModifiableVariableProperty()
    private ModifiableByteArray iv; // 16 Byte

    // Encrypted 128-bit AES in CBC mode with the given IV.
    @ModifiableVariableProperty()
    private ModifiableByteArray encryptedState; // x * 16 Byte

    // HMAC-SHA1 over key_name (16 octets)and IV (16 octets), followed
    // by the length of the encrypted_state field (2 octets) and its
    // contents (variable length).
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    private ModifiableByteArray mac; // 32 Byte

    public SessionTicket() {
    }

    public ModifiableByteArray getKeyName() {
        return keyName;
    }

    public void setKeyName(ModifiableByteArray keyName) {
        this.keyName = keyName;
    }

    public void setKeyName(byte[] keyName) {
        this.keyName = ModifiableVariableFactory.safelySetValue(this.keyName, keyName);
    }

    public ModifiableByteArray getIV() {
        return iv;
    }

    public void setIV(ModifiableByteArray iv) {
        this.iv = iv;
    }

    public void setIV(byte[] iv) {
        this.iv = ModifiableVariableFactory.safelySetValue(this.iv, iv);
    }

    public ModifiableByteArray getEncryptedState() {
        return encryptedState;
    }

    public void setEncryptedState(ModifiableByteArray encryptedState) {
        this.encryptedState = encryptedState;
    }

    public void setEncryptedState(byte[] encryptedState) {
        this.encryptedState = ModifiableVariableFactory.safelySetValue(this.encryptedState, encryptedState);
    }

    public ModifiableByteArray getMAC() {
        return mac;
    }

    public void setMAC(ModifiableByteArray mac) {
        this.mac = mac;
    }

    public void setMAC(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\n    KeyName: ");
        if (keyName != null) {
            sb.append(ArrayConverter.bytesToHexString(keyName.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n    IV: ");
        if (iv != null) {
            sb.append(ArrayConverter.bytesToHexString(iv.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n    EncryptedState: ");
        if (encryptedState != null) {
            sb.append(ArrayConverter.bytesToHexString(encryptedState.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n    MAC: ");
        if (mac != null) {
            sb.append(ArrayConverter.bytesToHexString(mac.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }
}