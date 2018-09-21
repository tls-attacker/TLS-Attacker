/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownHandshakePreparator extends HandshakeMessagePreparator<UnknownHandshakeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final UnknownHandshakeMessage msg;

    public UnknownHandshakePreparator(Chooser chooser, UnknownHandshakeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing UnknownHandshakeMessage");
        prepareData(msg);
    }

    private void prepareData(UnknownHandshakeMessage msg) {
        if (msg.getDataConfig() != null) {
            msg.setData(msg.getDataConfig());
        } else {
            msg.setData(new byte[0]);
        }
        LOGGER.debug("Data: " + ArrayConverter.bytesToHexString(msg.getData().getValue()));
    }

}
