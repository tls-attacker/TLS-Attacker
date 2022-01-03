/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ForwardMessagesWithPrepareAction extends ForwardMessagesAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ForwardMessagesWithPrepareAction() {
        withPrepare = true;
    }

    protected ForwardMessagesWithPrepareAction(String receiveFromAlias, String forwardToAlias) {
        super(receiveFromAlias, forwardToAlias);
        withPrepare = true;
    }

    public ForwardMessagesWithPrepareAction(String receiveFromAlias, String forwardToAlias,
        List<ProtocolMessage> messages) {
        super(receiveFromAlias, forwardToAlias, messages);
        withPrepare = true;
    }

    public ForwardMessagesWithPrepareAction(String receiveFromAlias, String forwardToAlias,
        ProtocolMessage... messages) {
        super(receiveFromAlias, forwardToAlias, messages);
        withPrepare = true;
    }

}
