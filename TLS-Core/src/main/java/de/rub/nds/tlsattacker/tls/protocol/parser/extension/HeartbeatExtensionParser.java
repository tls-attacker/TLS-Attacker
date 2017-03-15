/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatExtensionParser extends ExtensionParser<HeartbeatExtensionMessage>{

    public HeartbeatExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public HeartbeatExtensionMessage parse() {
        HeartbeatExtensionMessage msg = new HeartbeatExtensionMessage();
        parseExtensionType(msg);
        parseExtensionLength(msg);
        msg.setHeartbeatMode(parseByteArrayField(ExtensionByteLength.HEARTBEAT_MODE_LENGTH));
        return msg;
    }
    
}
