/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSpecPreparator extends ProtocolMessagePreparator<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");
    
    private final ChangeCipherSpecMessage message;
    private final byte CCS_PROTOCOL_TYPE = 1;

    public ChangeCipherSpecPreparator(TlsContext context, ChangeCipherSpecMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        message.setCcsProtocolType(CCS_PROTOCOL_TYPE);
    }

}
