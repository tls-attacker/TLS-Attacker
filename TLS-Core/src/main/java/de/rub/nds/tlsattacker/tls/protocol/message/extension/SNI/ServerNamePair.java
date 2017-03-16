/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.extension.SNI;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import java.io.Serializable;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNamePair extends ModifiableVariableHolder implements Serializable {

    private byte serverNameTypeConfig;
    private byte[] serverNameConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte serverNameType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger serverNameLength;

    @ModifiableVariableProperty
    private ModifiableByteArray serverName;

    public ServerNamePair() {
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
}
