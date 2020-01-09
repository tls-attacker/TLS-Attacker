/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class ClientEsniInnerParser extends Parser<ClientEsniInner> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ClientEsniInner clientEsniInner;

    public ClientEsniInnerParser(int startposition, byte[] array) {
        super(startposition, array);
        clientEsniInner = new ClientEsniInner();
    }

    @Override
    public ClientEsniInner parse() {
        parseClientNonce(clientEsniInner);
        parseServerNameListLength(clientEsniInner);
        parseServerNameListByte(clientEsniInner);
        parsePadding(clientEsniInner);
        parseServerNameList(clientEsniInner);
        return clientEsniInner;
    }

    private void parseClientNonce(ClientEsniInner clientEsniInne) {
        byte[] clientNonce = parseByteArrayField(ExtensionByteLength.NONCE);
        clientEsniInne.setClientNonce(clientNonce);
        LOGGER.debug("clientNonce: " + ArrayConverter.bytesToHexString(clientEsniInne.getClientNonce().getValue()));

    }

    private void parseServerNameListLength(ClientEsniInner clientEsniInne) {
        int serverNameListLength = parseIntField(ExtensionByteLength.SERVER_NAME_LIST);
        clientEsniInne.setServerNameListLength(serverNameListLength);
        LOGGER.debug("serverNameListLength: " + clientEsniInne.getServerNameListLength().getValue());
    }

    private void parseServerNameListByte(ClientEsniInner clientEsniInne) {
        byte[] serverNameListByte = parseByteArrayField(clientEsniInne.getServerNameListLength().getValue());
        clientEsniInne.setServerNameListBytes(serverNameListByte);
        LOGGER.debug("serverNameListByte: "
                + ArrayConverter.bytesToHexString(clientEsniInne.getServerNameListBytes().getValue()));
    }

    private void parsePadding(ClientEsniInner clientEsniInne) {
        byte[] padding = parseByteArrayField(this.getBytesLeft());
        clientEsniInne.setPadding(padding);
        LOGGER.debug("padding: " + ArrayConverter.bytesToHexString(clientEsniInne.getPadding().getValue()));
    }

    private void parseServerNameList(ClientEsniInner clientEsniInne) {
        int position = 0;
        List<ServerNamePair> serverNamePairList = new LinkedList<>();
        while (position < clientEsniInne.getServerNameListLength().getValue()) {
            ServerNamePairParser parser = new ServerNamePairParser(position, clientEsniInne.getServerNameListBytes()
                    .getValue());
            serverNamePairList.add(parser.parse());
            if (position == parser.getPointer()) {
                throw new ParserException("Ran into infinite Loop while parsing ServerNamePair");
            }
            position = parser.getPointer();
        }
        clientEsniInne.setServerNameList(serverNamePairList);
    }
}
