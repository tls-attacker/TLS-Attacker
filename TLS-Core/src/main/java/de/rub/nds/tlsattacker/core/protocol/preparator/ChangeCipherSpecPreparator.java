/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSpecPreparator extends ProtocolMessagePreparator<ChangeCipherSpecMessage> {

    private final ChangeCipherSpecMessage msg;
    private final byte CCS_PROTOCOL_TYPE = 1;

    public ChangeCipherSpecPreparator(TlsContext context, ChangeCipherSpecMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareCcsProtocolType(msg);
    }

    private void prepareCcsProtocolType(ChangeCipherSpecMessage msg) {
        msg.setCcsProtocolType(CCS_PROTOCOL_TYPE);
        LOGGER.debug("CCSProtocollType: " + msg.getCcsProtocolType().getValue());
    }

}
