/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ClientMasterKeyHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.RSAClientComputations;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ClientMasterKeyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.SSL2ClientMasterKeySerializer;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;

@SuppressWarnings("serial")
@XmlRootElement(name = "SSL2ClientMasterKey")
public class SSL2ClientMasterKeyMessage extends SSL2Message {

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

    @HoldsModifiableVariable @XmlElement private RSAClientComputations computations;

    public SSL2ClientMasterKeyMessage() {
        super(SSL2MessageType.SSL_CLIENT_MASTER_KEY);
    }

    @Override
    public String toCompactString() {
        return "SSL2 ClientMasterKey Message";
    }

    @Override
    public SSL2ClientMasterKeyHandler getHandler(TlsContext tlsContext) {
        return new SSL2ClientMasterKeyHandler(tlsContext);
    }

    @Override
    public ProtocolMessageParser<SSL2ClientMasterKeyMessage> getParser(
            TlsContext tlsContext, InputStream stream) {
        // We currently don't receive ClientMasterKey messages, only send them.
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public SSL2ClientMasterKeyPreparator getPreparator(TlsContext tlsContext) {
        return new SSL2ClientMasterKeyPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SSL2ClientMasterKeySerializer getSerializer(TlsContext tlsContext) {
        return new SSL2ClientMasterKeySerializer(this);
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
        this.clearKeyLength =
                ModifiableVariableFactory.safelySetValue(this.clearKeyLength, clearKeyLength);
    }

    public void setClearKeyLength(ModifiableInteger clearKeyLength) {
        this.clearKeyLength = clearKeyLength;
    }

    public ModifiableInteger getEncryptedKeyLength() {
        return encryptedKeyLength;
    }

    public void setEncryptedKeyLength(int encryptedKeyLength) {
        this.encryptedKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptedKeyLength, encryptedKeyLength);
    }

    public void setEncryptedKeyLength(ModifiableInteger encryptedKeyLength) {
        this.encryptedKeyLength = encryptedKeyLength;
    }

    public ModifiableInteger getKeyArgLength() {
        return keyArgLength;
    }

    public void setKeyArgLength(int keyArgLength) {
        this.keyArgLength =
                ModifiableVariableFactory.safelySetValue(this.keyArgLength, keyArgLength);
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
        this.clearKeyData =
                ModifiableVariableFactory.safelySetValue(this.clearKeyData, clearKeyData);
    }

    public ModifiableByteArray getEncryptedKeyData() {
        return encryptedKeyData;
    }

    public void setEncryptedKeyData(ModifiableByteArray encryptedKeyData) {
        this.encryptedKeyData = encryptedKeyData;
    }

    public void setEncryptedKeyData(byte[] encryptedKeyData) {
        this.encryptedKeyData =
                ModifiableVariableFactory.safelySetValue(this.encryptedKeyData, encryptedKeyData);
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
            sb.append("\n Clear Key Data: ")
                    .append(ArrayConverter.bytesToHexString(getClearKeyData().getValue()));
        }
        if (getEncryptedKeyData() != null && getEncryptedKeyData().getValue() != null) {
            sb.append("\n Encrypted Key Data: ")
                    .append(ArrayConverter.bytesToHexString(getEncryptedKeyData().getValue()));
        }
        if (getKeyArgData() != null && getKeyArgData().getValue() != null) {
            sb.append("\n Key Arg Data: ")
                    .append(ArrayConverter.bytesToHexString(getKeyArgData().getValue()));
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "SSL2_CMKM";
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> allModifiableVariableHolders =
                super.getAllModifiableVariableHolders();
        if (computations != null) {
            allModifiableVariableHolders.add(computations);
        }
        return allModifiableVariableHolders;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 29 * hash + Objects.hashCode(this.cipherKind);
        hash = 29 * hash + Objects.hashCode(this.clearKeyLength);
        hash = 29 * hash + Objects.hashCode(this.encryptedKeyLength);
        hash = 29 * hash + Objects.hashCode(this.keyArgLength);
        hash = 29 * hash + Objects.hashCode(this.clearKeyData);
        hash = 29 * hash + Objects.hashCode(this.encryptedKeyData);
        hash = 29 * hash + Objects.hashCode(this.keyArgData);
        hash = 29 * hash + Objects.hashCode(this.computations);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SSL2ClientMasterKeyMessage other = (SSL2ClientMasterKeyMessage) obj;
        if (!Objects.equals(this.cipherKind, other.cipherKind)) {
            return false;
        }
        if (!Objects.equals(this.clearKeyLength, other.clearKeyLength)) {
            return false;
        }
        if (!Objects.equals(this.encryptedKeyLength, other.encryptedKeyLength)) {
            return false;
        }
        if (!Objects.equals(this.keyArgLength, other.keyArgLength)) {
            return false;
        }
        if (!Objects.equals(this.clearKeyData, other.clearKeyData)) {
            return false;
        }
        if (!Objects.equals(this.encryptedKeyData, other.encryptedKeyData)) {
            return false;
        }
        if (!Objects.equals(this.keyArgData, other.keyArgData)) {
            return false;
        }
        return Objects.equals(this.computations, other.computations);
    }
}
