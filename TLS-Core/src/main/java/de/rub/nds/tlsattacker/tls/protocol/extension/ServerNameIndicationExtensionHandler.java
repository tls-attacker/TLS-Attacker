/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerNameIndicationExtensionHandler extends ExtensionHandler<ServerNameIndicationExtensionMessage> {

    /**
     * Server Name list length
     */
    public static final int SERVER_NAME_LIST_LENGTH = 2;

    /**
     * Server Name length
     */
    public static final int SERVER_NAME_LENGTH = 2;

    public ServerNameIndicationExtensionHandler() {

    }

    @Override
    public void prepareExtension(TlsContext context) {
        ServerNameIndicationExtensionMessage extension = (ServerNameIndicationExtensionMessage) extensionMessage;
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
                .intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS_LENGTH),
                ArrayConverter.intToBytes(extension.getServerNameListLength().getValue(), SERVER_NAME_LIST_LENGTH),
                new byte[] { extension.getServerNameType().getValue() }, ArrayConverter.intToBytes(extension
                        .getServerNameLength().getValue(), SERVER_NAME_LENGTH), extension.getServerName().getValue());

        extension.setExtensionBytes(sniExtension);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
        throw new UnsupportedOperationException("Server name indication extension parsing not supported yet.");
    }

}
