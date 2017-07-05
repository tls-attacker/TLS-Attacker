/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatExtensionPreparator extends ExtensionPreparator<HeartbeatExtensionMessage> {

    private final HeartbeatExtensionMessage msg;

    public HeartbeatExtensionPreparator(TlsContext context, HeartbeatExtensionMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing HeartbeatExtensionMessage");
        prepareHeartbeatMode(msg);
    }

    private void prepareHeartbeatMode(HeartbeatExtensionMessage msg) {
        msg.setHeartbeatMode(context.getConfig().getHeartbeatMode().getArrayValue());
        LOGGER.debug("HeartbeatMode: " + ArrayConverter.bytesToHexString(msg.getHeartbeatMode().getValue()));
    }

}
