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
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "PopAndSendRecord")
public class PopAndSendRecordAction extends CommonSendAction {

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
        TlsContext tlsContext =
                state.getContext(connectionAlias)
                        .getTlsContext(); // TODO this assumes that TLS is ran on top of TCP
        TcpContext tcpContext = state.getContext(connectionAlias).getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        Record record = tlsContext.getRecordBuffer().pop();
        String sending = record.getContentMessageType().name();
        if (connectionAlias == null) {
            LOGGER.info("Sending record: {}", sending);
        } else {
            LOGGER.info("Sending record({}): {}", connectionAlias, sending);
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
        return super.executedAsPlanned() && Objects.equals(asPlanned, Boolean.TRUE);
    }

    @Override
    public void reset() {
        super.reset();
        asPlanned = null;
    }

    @Override
    protected List<LayerConfiguration> createLayerConfiguration(TlsContext tlsContext) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createLayerConfiguration'");
    }
}
