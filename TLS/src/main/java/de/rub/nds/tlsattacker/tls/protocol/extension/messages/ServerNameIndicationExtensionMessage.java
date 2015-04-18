/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.extension.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.NameType;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ServerNameIndicationExtensionHandler;

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

    public ServerNameIndicationExtensionMessage() {
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
    public ExtensionHandler getExtensionHandler() {
	return ServerNameIndicationExtensionHandler.getInstance();
    }

}
