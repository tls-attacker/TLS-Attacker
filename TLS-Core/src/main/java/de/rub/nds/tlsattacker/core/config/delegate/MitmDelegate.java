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

import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

/**
 *
 * @author Lucas Hartmann <firstname.lastname@rub.de>
 */
public class MitmDelegate extends Delegate {

    @Parameter(names = "-port", required = true, description = "Mitm port")
    // TODO validator
    protected Integer port = null;

    public MitmDelegate() {
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        if (port != null) {
            config.setPort(port);
        }
        config.setConnectionEndType(ConnectionEndType.SERVER);
    }

}
