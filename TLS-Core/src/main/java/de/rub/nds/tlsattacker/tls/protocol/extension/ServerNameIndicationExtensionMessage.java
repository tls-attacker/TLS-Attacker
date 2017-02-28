/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.NameType;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;

/**
 * Describes Server Name Indication extension from
 * http://tools.ietf.org/html/rfc6066
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerNameIndicationExtensionMessage extends ExtensionMessage {

    private NameType nameTypeConfig;

    private String serverNameConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger serverNameListLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte serverNameType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger serverNameLength;

    @ModifiableVariableProperty
    ModifiableByteArray serverName;

    public ServerNameIndicationExtensionMessage(TlsConfig tlsConfig) {
        super();
        this.extensionTypeConstant = ExtensionType.SERVER_NAME_INDICATION;
    }

    public NameType getNameTypeConfig() {
        return nameTypeConfig;
    }

    public void setNameTypeConfig(NameType nameTypeConfig) {
        this.nameTypeConfig = nameTypeConfig;
    }

    public ModifiableInteger getServerNameListLength() {
        return serverNameListLength;
    }

    public void setServerNameListLength(ModifiableInteger serverNameListLength) {
        this.serverNameListLength = serverNameListLength;
    }

    public void setServerNameListLength(int length) {
        this.serverNameListLength = ModifiableVariableFactory.safelySetValue(serverNameListLength, length);
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

    public String getServerNameConfig() {
        return serverNameConfig;
    }

    public void setServerNameConfig(String serverNameConfig) {
        this.serverNameConfig = serverNameConfig;
    }

    @Override
    public ExtensionPreparator<? extends ExtensionMessage> getExtensionPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public ExtensionSerializer<? extends ExtensionMessage> getExtensionSerializer() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

}
