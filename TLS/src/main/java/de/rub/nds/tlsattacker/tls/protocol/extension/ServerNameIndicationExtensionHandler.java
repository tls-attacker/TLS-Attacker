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
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerNameIndicationExtensionHandler extends ExtensionHandler<ServerNameIndicationExtensionMessage> {

    private static ServerNameIndicationExtensionHandler instance;

    /**
     * Server Name list length
     */
    public static final int SERVER_NAME_LIST_LENGTH = 2;

    /**
     * Server Name length
     */
    public static final int SERVER_NAME_LENGTH = 2;

    private ServerNameIndicationExtensionHandler() {

    }

    public static ServerNameIndicationExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new ServerNameIndicationExtensionHandler();
	}
	return instance;
    }

    @Override
    public void initializeClientHelloExtension(ServerNameIndicationExtensionMessage extension) {
	byte serverNameType = extension.getNameTypeConfig().getValue();
	byte[] serverName = extension.getServerNameConfig().getBytes();

	extension.setExtensionType(ExtensionType.SERVER_NAME_INDICATION.getValue());
	extension.setServerNameType(serverNameType);
	extension.setServerName(serverName);
	extension.setServerNameLength(extension.getServerName().getValue().length);

	extension.setServerNameLength(extension.getServerNameLength().getValue());
	extension.setServerNameListLength(1 + SERVER_NAME_LIST_LENGTH + extension.getServerNameLength().getValue());

	extension.setExtensionLength(SERVER_NAME_LIST_LENGTH + extension.getServerNameListLength().getValue());

	byte[] sniExtension = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
		.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
		.intToBytes(extension.getServerNameListLength().getValue(), SERVER_NAME_LIST_LENGTH),
		new byte[] { extension.getServerNameType().getValue() }, ArrayConverter.intToBytes(extension
			.getServerNameLength().getValue(), SERVER_NAME_LENGTH), extension.getServerName().getValue());

	extension.setExtensionBytes(sniExtension);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }

}
