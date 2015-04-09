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

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.extension.handlers.HeartbeatExtensionHandler;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatExtensionMessage extends ExtensionMessage {

    private HeartbeatMode heartbeatModeConfig;

    ModifiableVariable<byte[]> heartbeatMode;

    public HeartbeatExtensionMessage() {
	this.extensionTypeConstant = ExtensionType.HEARTBEAT;
    }

    public ModifiableVariable<byte[]> getHeartbeatMode() {
	return heartbeatMode;
    }

    public void setHeartbeatMode(ModifiableVariable<byte[]> heartbeatMode) {
	this.heartbeatMode = heartbeatMode;
    }

    public void setHeartbeatMode(byte[] heartbeatMode) {
	if (this.heartbeatMode == null) {
	    this.heartbeatMode = new ModifiableVariable<>();
	}
	this.heartbeatMode.setOriginalValue(heartbeatMode);
    }

    public HeartbeatMode getHeartbeatModeConfig() {
	return heartbeatModeConfig;
    }

    public void setHeartbeatModeConfig(HeartbeatMode heartbeatModeConfig) {
	this.heartbeatModeConfig = heartbeatModeConfig;
    }

    @Override
    public ExtensionHandler getExtensionHandler() {
	return HeartbeatExtensionHandler.getInstance();
    }

}
