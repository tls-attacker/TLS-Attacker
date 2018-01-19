/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class PopAndSendRecordAction extends MessageAction implements SendingAction {

    public PopAndSendRecordAction() {
        super();
    }

    public PopAndSendRecordAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException, IOException {
        TlsContext tlsContext = state.getTlsContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        AbstractRecord record = tlsContext.getRecordBuffer().pop();
        String sending = record.getContentMessageType().name();
        if (connectionAlias == null) {
            LOGGER.info("Sending record: " + sending);
        } else {
            LOGGER.info("Sending record(" + connectionAlias + "): " + sending);
        }
        AbstractRecordSerializer s = record.getRecordSerializer();
        tlsContext.getTransportHandler().sendData(s.serialize());
        setExecuted(true);
    }

    @Override
    public String toString() {
        return "PopAndSendRecordAction";
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void setRecords(List<AbstractRecord> records) {
        this.records = records;
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        records = new LinkedList<>();
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<AbstractRecord> getSendRecords() {
        return records;
    }

}
