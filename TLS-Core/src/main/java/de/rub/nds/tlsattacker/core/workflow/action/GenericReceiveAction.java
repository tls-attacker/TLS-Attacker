/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
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
            throw new WorkflowExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving Messages...");
        TlsContext ctx = state.getTlsContext(getConnectionAlias());
        MessageActionResult result = receiveMessageHelper.receiveMessages(ctx);
        records = new ArrayList<>(result.getRecordList());
        messages = new ArrayList<>(result.getMessageList());
        if (result.getMessageFragmentList() != null) {
            fragments = new ArrayList<>(result.getMessageFragmentList());
        }
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
    public List<AbstractRecord> getReceivedRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return fragments;
    }

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
    }
}
