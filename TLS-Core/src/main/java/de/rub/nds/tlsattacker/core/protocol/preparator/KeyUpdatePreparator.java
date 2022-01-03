/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdatePreparator extends HandshakeMessagePreparator<KeyUpdateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final KeyUpdateMessage msg;

    public KeyUpdatePreparator(Chooser chooser, KeyUpdateMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        if (msg.getRequestMode() == null) {
            msg.setRequestMode(chooser.getConfig().getDefaultKeyUpdateRequestMode());
        }
        LOGGER.debug("Preparing KeyUpdate - MessageContent is: " + msg.getRequestMode().getValue());
    }

}
