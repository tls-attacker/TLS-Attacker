/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class ActionExecutor {

    protected static final Logger LOGGER = LogManager.getLogger(ActionExecutor.class.getName());

    public abstract MessageActionResult sendMessages(List<ProtocolMessage> messages, List<AbstractRecord> records);

    public abstract MessageActionResult receiveMessages(List<ProtocolMessage> messages);

}
