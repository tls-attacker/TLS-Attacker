/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.IOException;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class ActionExecutor {
    public abstract List<ProtocolMessage> sendMessages(List<ProtocolMessage> messages);

    public abstract List<ProtocolMessage> receiveMessages(List<ProtocolMessage> messages);

}
