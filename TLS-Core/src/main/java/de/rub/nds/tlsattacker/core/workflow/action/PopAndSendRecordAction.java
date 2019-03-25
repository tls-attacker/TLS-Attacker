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
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PopAndSendRecordAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();
    private Boolean asPlanned = null;

    public PopAndSendRecordAction() {
        super();
    }

    public PopAndSendRecordAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
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
        try {
            tlsContext.getTransportHandler().sendData(s.serialize());
            asPlanned = true;
        } catch (IOException ex) {
            LOGGER.debug(ex);
            tlsContext.setReceivedTransportHandlerException(true);
            asPlanned = false;
        }
        setExecuted(true);
    }

    @Override
    public String toString() {
        return "PopAndSendRecordAction";
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted() && Objects.equals(asPlanned, Boolean.TRUE);
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
        asPlanned = null;
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
