/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TransportHandlerDelegate extends Delegate {

    @Parameter(names = "-transport_handler_type", description = "Transport Handler type")
    private TransportHandlerType transportHandlerType = TransportHandlerType.TCP;

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
        config.setTransportHandlerType(transportHandlerType);
    }
}
