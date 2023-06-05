/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class GenericReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public GenericReceiveAction() {
        super();
    }

    public GenericReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving Messages...");
        TlsContext ctx = state.getContext(getConnectionAlias()).getTlsContext();
        receive(ctx, null, null, null, null);

        setExecuted(true);
        String received = getReadableString(messages);
        LOGGER.info("Received Messages (" + ctx + "): " + received);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Receive Action:\n");
        sb.append("\tActual:");
        for (ProtocolMessage message : messages) {
            sb.append(message.toCompactString());
            sb.append(", ");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        records = new LinkedList<>();
        fragments = new LinkedList<>();
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<Record> getReceivedRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return fragments;
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        return httpMessages;
    }
}
