/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
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
package de.rub.nds.tlsattacker.tls.protocol.extension.handlers;

import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatExtensionHandler extends ExtensionHandler<HeartbeatExtensionMessage> {

    private static HeartbeatExtensionHandler instance;

    private HeartbeatExtensionHandler() {

    }

    public static HeartbeatExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new HeartbeatExtensionHandler();
	}
	return instance;
    }

    @Override
    public void initializeClientHelloExtension(HeartbeatExtensionMessage extension) {
	byte[] heartbeatMode = { extension.getHeartbeatModeConfig().getValue() };

	extension.setExtensionType(ExtensionType.HEARTBEAT.getValue());
	extension.setHeartbeatMode(heartbeatMode);

	extension.setExtensionLength(extension.getHeartbeatMode().getValue().length);

	byte[] pfExtension = ArrayConverter.concatenate(extension.getExtensionType().getValue(),
		ArrayConverter.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS),
		extension.getHeartbeatMode().getValue());

	extension.setExtensionBytes(pfExtension);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	if (extensionMessage == null) {
	    extensionMessage = new HeartbeatExtensionMessage();
	}
	HeartbeatExtensionMessage hem = (HeartbeatExtensionMessage) extensionMessage;
	int nextPointer = pointer + ExtensionByteLength.TYPE;
	byte[] extensionType = Arrays.copyOfRange(message, pointer, nextPointer);
	hem.setExtensionType(extensionType);

	pointer = nextPointer;
	nextPointer = pointer + ExtensionByteLength.EXTENSIONS;
	int extensionLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, pointer, nextPointer));
	hem.setExtensionLength(extensionLength);

	pointer = nextPointer;
	byte[] mode = { message[pointer] };
	hem.setHeartbeatMode(mode);

	byte[] result = ArrayConverter.concatenate(hem.getExtensionType().getValue(), ArrayConverter.intToBytes(hem
		.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), hem.getHeartbeatMode().getValue());
	hem.setExtensionBytes(result);

	return pointer + 1;
    }

}
