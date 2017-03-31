/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessagePreparator extends HandshakeMessagePreparator<UnknownHandshakeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    private final UnknownHandshakeMessage msg;

    public UnknownHandshakeMessagePreparator(TlsContext context, UnknownHandshakeMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        prepareData(msg);
    }

    private void prepareData(UnknownHandshakeMessage msg) {
        msg.setData(msg.getDataConfig());
        LOGGER.debug("Data: "+ Arrays.toString(msg.getData().getValue()));
    }

}
