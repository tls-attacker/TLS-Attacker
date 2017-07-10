/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNameIndicationExtensionParser extends ExtensionParser<ServerNameIndicationExtensionMessage> {

    private List<ServerNamePair> pairList;

    public ServerNameIndicationExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(ServerNameIndicationExtensionMessage msg) {
        parseServerNameListLength(msg);
        parseServerNameListBytes(msg);
        int position = 0;
        pairList = new LinkedList<>();
        while (position < msg.getServerNameListLength().getValue()) {
            ServerNamePairParser parser = new ServerNamePairParser(position, msg.getServerNameListBytes().getValue());
            pairList.add(parser.parse());
            position = parser.getPointer();
        }
        parseServerNameList(msg);
    }

    @Override
    protected ServerNameIndicationExtensionMessage createExtensionMessage() {
        return new ServerNameIndicationExtensionMessage();
    }

    /**
     * Reads the next bytes as the serverNameListlength of the Extension and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameListLength(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListLength(parseIntField(ExtensionByteLength.SERVER_NAME_LIST));
        LOGGER.debug("ServerNameListLength: " + msg.getServerNameListLength().getValue());
    }

    /**
     * Reads the next bytes as the serverNameListBytes of the Extension and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameListBytes(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameListBytes(parseByteArrayField(msg.getServerNameListLength().getValue()));
        LOGGER.debug("ServerNameListBytes: " + ArrayConverter.bytesToHexString(msg.getServerNameListBytes().getValue()));
    }

    /**
     * Reads the next bytes as the serverNameList of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseServerNameList(ServerNameIndicationExtensionMessage msg) {
        msg.setServerNameList(pairList);
    }
}
