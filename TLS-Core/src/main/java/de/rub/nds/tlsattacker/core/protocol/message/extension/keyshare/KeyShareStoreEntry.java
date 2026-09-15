/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.Serializable;
import java.util.Arrays;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyShareStoreEntry implements Serializable {

    private NamedGroup group;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] publicKey;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] dhPublicKey;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] mlKemPublicKey;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] mlKemCiphertext;

    public KeyShareStoreEntry() {}

    public KeyShareStoreEntry(NamedGroup group, byte[] publicKey) {
        this.group = group;
        this.publicKey = publicKey;
    }

    /**
     * Creates a store entry from a parsed or prepared KeyShareEntry, carrying over the components
     * the key share consists of. Components the entry does not provide remain null.
     */
    public KeyShareStoreEntry(KeyShareEntry entry) {
        this.group = entry.getGroupConfig();
        this.publicKey = valueOrNull(entry.getPublicKey());
        this.dhPublicKey = valueOrNull(entry.getDhPublicKey());
        this.mlKemPublicKey = valueOrNull(entry.getMlKemPublicKey());
        this.mlKemCiphertext = valueOrNull(entry.getMlKemCiphertext());
    }

    private static byte[] valueOrNull(ModifiableByteArray modifiableByteArray) {
        if (modifiableByteArray == null) {
            return null;
        }
        return modifiableByteArray.getValue();
    }

    public NamedGroup getGroup() {
        return group;
    }

    public void setGroup(NamedGroup group) {
        this.group = group;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    /** The classical (EC)DH share of this key share, or null if the group has no classical part. */
    public byte[] getDhPublicKey() {
        return dhPublicKey;
    }

    public void setDhPublicKey(byte[] dhPublicKey) {
        this.dhPublicKey = dhPublicKey;
    }

    /** The ML-KEM encapsulation key, set for client key shares of ML-KEM and hybrid groups. */
    public byte[] getMlKemPublicKey() {
        return mlKemPublicKey;
    }

    public void setMlKemPublicKey(byte[] mlKemPublicKey) {
        this.mlKemPublicKey = mlKemPublicKey;
    }

    /** The ML-KEM ciphertext, set for server key shares of ML-KEM and hybrid groups. */
    public byte[] getMlKemCiphertext() {
        return mlKemCiphertext;
    }

    public void setMlKemCiphertext(byte[] mlKemCiphertext) {
        this.mlKemCiphertext = mlKemCiphertext;
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
        final KeyShareStoreEntry other = (KeyShareStoreEntry) obj;
        if (this.group != other.group) {
            return false;
        }
        return Arrays.equals(this.publicKey, other.publicKey);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + (this.group != null ? this.group.hashCode() : 0);
        hash = 97 * hash + Arrays.hashCode(this.publicKey);
        return hash;
    }
}
