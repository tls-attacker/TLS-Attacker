/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveAsciiAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String receivedAsciiString;

    public ReceiveAsciiAction() {
        super();
    }

    public ReceiveAsciiAction(String asciiText, String encoding) {
        super(asciiText, encoding);
        receivedAsciiString = null;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext();
        TcpContext tcpContext = state.getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        try {
            LOGGER.debug("Receiving ASCII message...");
            byte[] fetchData = tcpContext.getTransportHandler().fetchData();
            receivedAsciiString = new String(fetchData, getEncoding());
            LOGGER.info("Received: " + receivedAsciiString);

            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    public String getReceivedAsciiString() {
        return receivedAsciiString;
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return Objects.equals(receivedAsciiString, getAsciiText());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ReceiveAsciiAction that = (ReceiveAsciiAction) o;
        return Objects.equals(receivedAsciiString, that.receivedAsciiString);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), receivedAsciiString);
    }
}
