/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.converters.TransportHandlerTypeConverter;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/**
 * Note: This delegate should always be executed after the Protocolverion
 * delegate
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TransportHandlerDelegate extends Delegate {

    @Parameter(names = "-transport_handler_type", description = "Transport Handler type (TCP, EAP_TLS, UDP)", converter = TransportHandlerTypeConverter.class)
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
    public void applyDelegate(TlsConfig config) {
        if (transportHandlerType != null) {
            config.setTransportHandlerType(transportHandlerType);
        }
    }
}
