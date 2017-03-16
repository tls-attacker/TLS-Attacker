/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.extension;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
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
import java.util.LinkedList;
import java.util.List;

/**
 * Describes Server Name Indication extension from
 * http://tools.ietf.org/html/rfc6066
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerNameIndicationExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger serverNameListLength;

    @ModifiableVariableProperty
    private ModifiableByteArray serverNameListBytes;

    @HoldsModifiableVariable
    private List<ServerNamePair> serverNameList;

    public ServerNameIndicationExtensionMessage() {
        super();
        serverNameList = new LinkedList<>();
        this.extensionTypeConstant = ExtensionType.SERVER_NAME_INDICATION;
    }

    public ServerNameIndicationExtensionMessage(TlsConfig config) {
        super();
        serverNameList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair();
        pair.setServerNameConfig(config.getSniHostname().getBytes());
        pair.setServerNameTypeConfig(config.getSniType().getValue());
        serverNameList.add(pair);
        this.extensionTypeConstant = ExtensionType.SERVER_NAME_INDICATION;
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

    public ModifiableByteArray getServerNameListBytes() {
        return serverNameListBytes;
    }

    public void setServerNameListBytes(ModifiableByteArray serverNameListBytes) {
        this.serverNameListBytes = serverNameListBytes;
    }

    public void setServerNameListBytes(byte[] bytes) {
        this.serverNameListBytes = ModifiableVariableFactory.safelySetValue(serverNameListBytes, bytes);
    }

    public List<ServerNamePair> getServerNameList() {
        return serverNameList;
    }

    public void setServerNameList(List<ServerNamePair> serverNameList) {
        this.serverNameList = serverNameList;
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
