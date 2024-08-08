/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.connectionid;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.util.Objects;

@XmlAccessorType(XmlAccessType.FIELD)
public class ConnectionId extends ModifiableVariableHolder {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray connectionId;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    public ConnectionId() {}

    public ConnectionId(byte[] connectionId) {
        this.connectionId =
                ModifiableVariableFactory.safelySetValue(this.connectionId, connectionId);
        this.length = ModifiableVariableFactory.safelySetValue(this.length, connectionId.length);
    }

    public ConnectionId(ModifiableByteArray connectionId, ModifiableInteger length) {
        this.connectionId = connectionId;
        this.length = length;
    }

    public ModifiableByteArray getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(ModifiableByteArray connectionId) {
        this.connectionId = connectionId;
    }

    public void setConnectionId(byte[] connectionId) {
        this.connectionId =
                ModifiableVariableFactory.safelySetValue(this.connectionId, connectionId);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 47 * hash + Objects.hashCode(this.connectionId);
        hash = 47 * hash + Objects.hashCode(this.length);
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
        final ConnectionId other = (ConnectionId) obj;
        if (!Objects.equals(this.connectionId, other.connectionId)) {
            return false;
        }
        return Objects.equals(this.length, other.length);
    }
}
