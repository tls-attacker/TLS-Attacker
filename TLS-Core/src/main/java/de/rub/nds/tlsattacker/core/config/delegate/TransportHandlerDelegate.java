/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.TransportHandlerTypeConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

/**
 * Note: This delegate should always be executed after the Protocolverion
 * delegate
 */
public class TransportHandlerDelegate extends Delegate {

    @Parameter(names = "-transport_handler_type", description = "Transport Handler type", converter = TransportHandlerTypeConverter.class)
    private TransportHandlerType transportHandlerType = null;

    public TransportHandlerDelegate() {
    }

    public TransportHandlerType getTransportHandlerType() {
        return transportHandlerType;
    }

    public void setTransportHandlerType(TransportHandlerType transportHandlerType) {
        this.transportHandlerType = transportHandlerType;
    }

    @Override
    public void applyDelegate(Config config) {
        if (transportHandlerType == null) {
            return;
        }

        if (config.getDefaultClientConnection() == null) {
            config.setDefaultClientConnection(new OutboundConnection());
        }
        if (config.getDefaultServerConnection() == null) {
            config.setDefaultServerConnection(new InboundConnection());
        }

        config.getDefaultClientConnection().setTransportHandlerType(transportHandlerType);
        config.getDefaultServerConnection().setTransportHandlerType(transportHandlerType);
    }
}
