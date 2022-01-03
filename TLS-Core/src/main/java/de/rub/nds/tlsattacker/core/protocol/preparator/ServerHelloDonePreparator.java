/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloDonePreparator extends HandshakeMessagePreparator<ServerHelloDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerHelloDoneMessage message;

    public ServerHelloDonePreparator(Chooser chooser, ServerHelloDoneMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing ServerHelloDoneMessage");

    }

}
