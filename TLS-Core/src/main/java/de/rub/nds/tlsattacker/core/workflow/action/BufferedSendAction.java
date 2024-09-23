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
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "BufferedSend")
public class BufferedSendAction extends CommonSendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public BufferedSendAction() {
        super();
    }

    public BufferedSendAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        super.execute(state);
        state.getTlsContext(getConnectionAlias()).setMessageBuffer(new LinkedList<>());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("BufferedSend Action:\n");
        sb.append("Messages:\n");
        for (ProtocolMessage message : getSentMessages()) {
            sb.append(message.toCompactString());
            sb.append(", ");
        }
        return sb.toString();
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createLayerConfiguration'");
    }
}
