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
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class GenericReceiveAsciiAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    GenericReceiveAsciiAction() {}

    public GenericReceiveAsciiAction(String encoding) {
        super(encoding);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TcpContext tcpContext = state.getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        try {
            LOGGER.debug("Receiving ASCII message...");
            byte[] fetchData = tcpContext.getTransportHandler().fetchData();
            setAsciiText(new String(fetchData, getEncoding()));
            LOGGER.info("Received:" + getAsciiText());
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(false);
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
