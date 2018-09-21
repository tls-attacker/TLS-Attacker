/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ClientMasterKeyHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.RSAClientComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlElement;

@SuppressWarnings("serial")
public class SSL2ClientMasterKeyMessage extends SSL2HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray cipherKind;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger clearKeyLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger encryptedKeyLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger keyArgLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray clearKeyData;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray encryptedKeyData;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray keyArgData;

    @HoldsModifiableVariable
    @XmlElement
    private RSAClientComputations computations;

    public SSL2ClientMasterKeyMessage() {
        super(HandshakeMessageType.SSL2_CLIENT_MASTER_KEY);
    }

    public SSL2ClientMasterKeyMessage(Config config) {
        this();
    }

    @Override
    public String toCompactString() {
        return "SSL2 ClientMasterKey Message";
    }

    @Override
    public SSL2ClientMasterKeyHandler getHandler(TlsContext context) {
        return new SSL2ClientMasterKeyHandler(context);
    }

    public ModifiableByteArray getCipherKind() {
        return cipherKind;
    }

    public void setCipherKind(ModifiableByteArray cipherKind) {
        this.cipherKind = cipherKind;
    }

    public void setCipherKind(byte[] cipherKind) {
        this.cipherKind = ModifiableVariableFactory.safelySetValue(this.cipherKind, cipherKind);
    }

    public ModifiableInteger getClearKeyLength() {
        return clearKeyLength;
    }

    public void setClearKeyLength(int clearKeyLength) {
        this.clearKeyLength = ModifiableVariableFactory.safelySetValue(this.clearKeyLength, clearKeyLength);
    }

    public void setClearKeyLength(ModifiableInteger clearKeyLength) {
        this.clearKeyLength = clearKeyLength;
    }

    public ModifiableInteger getEncryptedKeyLength() {
        return encryptedKeyLength;
    }

    public void setEncryptedKeyLength(int encryptedKeyLength) {
        this.encryptedKeyLength = ModifiableVariableFactory.safelySetValue(this.encryptedKeyLength, encryptedKeyLength);
    }

    public void setEncryptedKeyLength(ModifiableInteger encryptedKeyLength) {
        this.encryptedKeyLength = encryptedKeyLength;
    }

    public ModifiableInteger getKeyArgLength() {
        return keyArgLength;
    }

    public void setKeyArgLength(int keyArgLength) {
        this.keyArgLength = ModifiableVariableFactory.safelySetValue(this.keyArgLength, keyArgLength);
    }

    public void setKeyArgLength(ModifiableInteger keyArgLength) {
        this.keyArgLength = keyArgLength;
    }

    public ModifiableByteArray getClearKeyData() {
        return clearKeyData;
    }

    public void setClearKeyData(ModifiableByteArray clearKeyData) {
        this.clearKeyData = clearKeyData;
    }

    public void setClearKeyData(byte[] clearKeyData) {
        this.clearKeyData = ModifiableVariableFactory.safelySetValue(this.clearKeyData, clearKeyData);
    }

    public ModifiableByteArray getEncryptedKeyData() {
        return encryptedKeyData;
    }

    public void setEncryptedKeyData(ModifiableByteArray encryptedKeyData) {
        this.encryptedKeyData = encryptedKeyData;
    }

    public void setEncryptedKeyData(byte[] encryptedKeyData) {
        this.encryptedKeyData = ModifiableVariableFactory.safelySetValue(this.encryptedKeyData, encryptedKeyData);
    }

    public ModifiableByteArray getKeyArgData() {
        return keyArgData;
    }

    public void setKeyArgData(ModifiableByteArray keyArgData) {
        this.keyArgData = keyArgData;
    }

    public void setKeyArgData(byte[] keyArgData) {
        this.keyArgData = ModifiableVariableFactory.safelySetValue(this.keyArgData, keyArgData);
    }

    public void prepareComputations() {
        if (computations == null) {
            computations = new RSAClientComputations();
        }
    }

    public RSAClientComputations getComputations() {
        return this.computations;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());

        if (getCipherKind() != null && getCipherKind().getValue() != null) {
            sb.append("\n Cipher Kind: ").append(getCipherKind().getValue());
        }
        if (getClearKeyData() != null && getClearKeyData().getValue() != null) {
            sb.append("\n Clear Key Data: ").append(ArrayConverter.bytesToHexString(getClearKeyData().getValue()));
        }
        if (getEncryptedKeyData() != null && getEncryptedKeyData().getValue() != null) {
            sb.append("\n Encrypted Key Data: ").append(
                    ArrayConverter.bytesToHexString(getEncryptedKeyData().getValue()));
        }
        if (getKeyArgData() != null && getKeyArgData().getValue() != null) {
            sb.append("\n Key Arg Data: ").append(ArrayConverter.bytesToHexString(getKeyArgData().getValue()));
        }
        return sb.toString();
    }
}
