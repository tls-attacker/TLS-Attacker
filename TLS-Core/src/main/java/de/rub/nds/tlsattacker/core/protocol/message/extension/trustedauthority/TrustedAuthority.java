/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TrustedAuthority extends ModifiableVariableHolder implements Serializable {

    @ModifiableVariableProperty
    private ModifiableByte identifierType;
    @ModifiableVariableProperty
    private ModifiableByteArray sha1Hash;
    @ModifiableVariableProperty
    private ModifiableInteger distinguishedNameLength;
    @ModifiableVariableProperty
    private ModifiableByteArray distinguishedName;

    private byte preparatorIdentifierType;
    private byte[] preparatorSha1Hash;
    private Integer preparatorDistinguishedNameLength;
    private byte[] preparatorDistinguishedName;

    public TrustedAuthority() {
    }

    public TrustedAuthority(byte preparatorIdentifierType, byte[] preparatorSha1Hash,
            Integer preparatorDistinguishedNameLength, byte[] preparatorDistinguishedName) {
        this.preparatorIdentifierType = preparatorIdentifierType;
        this.preparatorSha1Hash = preparatorSha1Hash;
        this.preparatorDistinguishedNameLength = preparatorDistinguishedNameLength;
        this.preparatorDistinguishedName = preparatorDistinguishedName;
    }

    /*
     * public TrustedAuthority(byte identifierType, byte[] sha1Hash, Integer
     * distinguishedNameLength, byte[] distinguishedName) { this.identifierType
     * = ModifiableVariableFactory.safelySetValue(this.identifierType,
     * identifierType); this.sha1Hash =
     * ModifiableVariableFactory.safelySetValue(this.sha1Hash, sha1Hash);
     * this.distinguishedNameLength =
     * ModifiableVariableFactory.safelySetValue(this.distinguishedNameLength,
     * distinguishedNameLength); this.distinguishedName =
     * ModifiableVariableFactory.safelySetValue(this.distinguishedName,
     * distinguishedName); }
     */
    public ModifiableByte getIdentifierType() {
        return identifierType;
    }

    public void setIdentifierType(ModifiableByte identifierType) {
        this.identifierType = identifierType;
    }

    public void setIdentifierType(byte identifierType) {
        this.identifierType = ModifiableVariableFactory.safelySetValue(this.identifierType, identifierType);
    }

    public ModifiableByteArray getSha1Hash() {
        return sha1Hash;
    }

    public void setSha1Hash(ModifiableByteArray sha1Hash) {
        this.sha1Hash = sha1Hash;
    }

    public void setSha1Hash(byte[] sha1Hash) {
        this.sha1Hash = ModifiableVariableFactory.safelySetValue(this.sha1Hash, sha1Hash);
    }

    public ModifiableInteger getDistinguishedNameLength() {
        return distinguishedNameLength;
    }

    public void setDistinguishedNameLength(ModifiableInteger distinguishedNameLength) {
        this.distinguishedNameLength = distinguishedNameLength;
    }

    public void setDistinguishedNameLength(int distinguishedNameLength) {
        this.distinguishedNameLength = ModifiableVariableFactory.safelySetValue(this.distinguishedNameLength,
                distinguishedNameLength);
    }

    public ModifiableByteArray getDistinguishedName() {
        return distinguishedName;
    }

    public void setDistinguishedName(ModifiableByteArray distinguishedName) {
        this.distinguishedName = distinguishedName;
    }

    public void setDistinguishedName(byte[] distinguishedName) {
        this.distinguishedName = ModifiableVariableFactory.safelySetValue(this.distinguishedName, distinguishedName);
    }

    public byte getPreparatorIdentifierType() {
        return preparatorIdentifierType;
    }

    public void setPreparatorIdentifierType(byte preparatorIdentifierType) {
        this.preparatorIdentifierType = preparatorIdentifierType;
    }

    public byte[] getPreparatorSha1Hash() {
        return preparatorSha1Hash;
    }

    public void setPreparatorSha1Hash(byte[] preparatorSha1Hash) {
        this.preparatorSha1Hash = preparatorSha1Hash;
    }

    public Integer getPreparatorDistinguishedNameLength() {
        return preparatorDistinguishedNameLength;
    }

    public void setPreparatorDistinguishedNameLength(int preparatorDistinguishedNameLength) {
        this.preparatorDistinguishedNameLength = preparatorDistinguishedNameLength;
    }

    public byte[] getPreparatorDistinguishedName() {
        return preparatorDistinguishedName;
    }

    public void setPreparatorDistinguishedName(byte[] preparatorDistinguishedName) {
        this.preparatorDistinguishedName = preparatorDistinguishedName;
    }

}
