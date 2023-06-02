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
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
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
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();
        TcpContext tcpContext = state.getContext(connectionAlias).getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        Record record = tlsContext.getRecordBuffer().pop();
        String sending = record.getContentMessageType().name();
        if (connectionAlias == null) {
            LOGGER.info("Sending record: " + sending);
        } else {
            LOGGER.info("Sending record(" + connectionAlias + "): " + sending);
        }
        RecordSerializer s = record.getRecordSerializer();
        try {
            tcpContext.getTransportHandler().sendData(s.serialize());
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
    public void setRecords(List<Record> records) {
        this.records = records;
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        records = new LinkedList<>();
        fragments = new LinkedList<>();
        setExecuted(null);
        asPlanned = null;
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<Record> getSendRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return fragments;
    }
}
