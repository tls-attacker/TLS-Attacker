/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare;

import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.io.Serializable;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyShareStoreEntry implements Serializable {

    private NamedGroup group;

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] publicKey;

    public KeyShareStoreEntry() {
    }

    public KeyShareStoreEntry(NamedGroup group, byte[] publicKey) {
        this.group = group;
        this.publicKey = publicKey;
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

}
