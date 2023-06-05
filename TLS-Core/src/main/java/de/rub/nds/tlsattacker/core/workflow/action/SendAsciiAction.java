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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class SendAsciiAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    SendAsciiAction() {
        super();
    }

    public SendAsciiAction(String asciiString, String encoding) {
        super(asciiString, encoding);
    }

    public SendAsciiAction(String encoding) {
        super(encoding);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext();
        TcpContext tcpContext = state.getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        try {
            LOGGER.info("Sending ASCII message: " + getAsciiText());
            tcpContext.getTransportHandler().sendData(getAsciiText().getBytes(getEncoding()));
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
