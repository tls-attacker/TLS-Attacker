/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension.sni;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

public class ServerNamePair extends ModifiableVariableHolder implements Serializable {

    private Byte serverNameTypeConfig;
    private byte[] serverNameConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte serverNameType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger serverNameLength;

    @ModifiableVariableProperty
    private ModifiableByteArray serverName;

    private ServerNamePair() {
    }

    public ServerNamePair(Byte typeConfig, byte[] serverNameConfig) {
        this.serverNameTypeConfig = typeConfig;
        this.serverNameConfig = serverNameConfig;
    }

    public ModifiableByte getServerNameType() {
        return serverNameType;
    }

    public void setServerNameType(ModifiableByte serverNameType) {
        this.serverNameType = serverNameType;
    }

    public void setServerNameType(byte serverNameType) {
        this.serverNameType = ModifiableVariableFactory.safelySetValue(this.serverNameType, serverNameType);
    }

    public ModifiableInteger getServerNameLength() {
        return serverNameLength;
    }

    public void setServerNameLength(ModifiableInteger serverNameLength) {
        this.serverNameLength = serverNameLength;
    }

    public void setServerNameLength(int serverNameLength) {
        this.serverNameLength = ModifiableVariableFactory.safelySetValue(this.serverNameLength, serverNameLength);
    }

    public ModifiableByteArray getServerName() {
        return serverName;
    }

    public void setServerName(ModifiableByteArray serverName) {
        this.serverName = serverName;
    }

    public void setServerName(byte[] serverName) {
        this.serverName = ModifiableVariableFactory.safelySetValue(this.serverName, serverName);
    }

    public byte getServerNameTypeConfig() {
        return serverNameTypeConfig;
    }

    public void setServerNameTypeConfig(byte serverNameTypeConfig) {
        this.serverNameTypeConfig = serverNameTypeConfig;
    }

    public byte[] getServerNameConfig() {
        return serverNameConfig;
    }

    public void setServerNameConfig(byte[] serverNameConfig) {
        this.serverNameConfig = serverNameConfig;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 13 * hash + Objects.hashCode(this.serverNameTypeConfig);
        hash = 13 * hash + Arrays.hashCode(this.serverNameConfig);
        hash = 13 * hash + Objects.hashCode(this.serverNameType);
        hash = 13 * hash + Objects.hashCode(this.serverNameLength);
        hash = 13 * hash + Objects.hashCode(this.serverName);
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
        final ServerNamePair other = (ServerNamePair) obj;
        if (!Objects.equals(this.serverNameTypeConfig, other.serverNameTypeConfig)) {
            return false;
        }
        if (!Arrays.equals(this.serverNameConfig, other.serverNameConfig)) {
            return false;
        }
        if (!Objects.equals(this.serverNameType, other.serverNameType)) {
            return false;
        }
        if (!Objects.equals(this.serverNameLength, other.serverNameLength)) {
            return false;
        }
        return Objects.equals(this.serverName, other.serverName);
    }

}
