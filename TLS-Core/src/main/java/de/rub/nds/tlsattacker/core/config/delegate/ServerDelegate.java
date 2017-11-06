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
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;


public class ServerDelegate extends Delegate {

    @Parameter(names = "-port", required = true, description = "ServerPort")
    protected Integer port = null;

    public ServerDelegate() {
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(int port) {
        if (port < 0 || port > 65535) {
            throw new ParameterException("port must be in interval [0,65535], but is " + port);
        }
        this.port = port;
    }

    @Override
    public void applyDelegate(Config config) {
        if (port == null) {
            // Though port is a required parameter we can get here if
            // we call applyDelegate manually, e.g. in tests.
            throw new ParameterException("port must be in interval [0,65535], but is " + port);
        }
        ServerConnectionEnd conEnd = new ServerConnectionEnd();
        conEnd.setAlias(Config.DEFAULT_CONNECTION_END_ALIAS);
        conEnd.setPort(port);
        config.clearConnectionEnds();
        config.addConnectionEnd(conEnd);
    }

}
