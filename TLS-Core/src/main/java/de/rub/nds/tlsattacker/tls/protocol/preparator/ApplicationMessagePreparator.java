/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ApplicationMessagePreparator extends ProtocolMessagePreparator<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    private final ApplicationMessage msg;

    public ApplicationMessagePreparator(TlsContext context, ApplicationMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareData(msg);
    }

    private void prepareData(ApplicationMessage msg) {
        msg.setData(context.getConfig().getDefaultApplicationMessageData().getBytes());
        LOGGER.debug("Data: " + Arrays.toString(msg.getData().getValue()));
    }

}
