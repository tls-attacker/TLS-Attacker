/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatExtensionParser extends ExtensionParser<HeartbeatExtensionMessage> {

    public HeartbeatExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(HeartbeatExtensionMessage msg) {
        msg.setHeartbeatMode(parseByteArrayField(ExtensionByteLength.HEARTBEAT_MODE_LENGTH));
    }

    @Override
    protected HeartbeatExtensionMessage createExtensionMessage() {
        return new HeartbeatExtensionMessage();
    }

}
