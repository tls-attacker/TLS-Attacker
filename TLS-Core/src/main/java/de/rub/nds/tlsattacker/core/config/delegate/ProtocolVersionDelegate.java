/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

public class ProtocolVersionDelegate extends Delegate {

    @Parameter(names = "-version", description = "Highest supported protocol version ")
    private ProtocolVersion protocolVersion = null;

    public ProtocolVersionDelegate() {
    }

    public ProtocolVersionDelegate(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    @Override
    public void applyDelegate(Config config) {
        if (protocolVersion == null) {
            return;
        }

        config.setHighestProtocolVersion(protocolVersion);
        config.setDefaultSelectedProtocolVersion(protocolVersion);
        TransportHandlerType th = TransportHandlerType.TCP;
        if (config.getHighestProtocolVersion().isDTLS()) {
            th = TransportHandlerType.UDP;
            config.setWorkflowExecutorType(WorkflowExecutorType.DTLS);
            config.setFinishWithCloseNotify(true);
            config.setIgnoreRetransmittedCssInDtls(true);
        }

        if (config.getDefaultClientConnection() == null) {
            config.setDefaultClientConnection(new OutboundConnection());
        }
        if (config.getDefaultServerConnection() == null) {
            config.setDefaultServerConnection(new InboundConnection());
        }
        config.getDefaultClientConnection().setTransportHandlerType(th);
        config.getDefaultServerConnection().setTransportHandlerType(th);
    }

}
