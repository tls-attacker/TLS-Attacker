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
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;

public class ServerDelegate extends Delegate {

    @Parameter(names = "-port", required = true, description = "ServerPort")
    protected Integer port = null;

    public ServerDelegate() {
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    @Override
    public void applyDelegate(Config config) {

        config.setDefaulRunningMode(RunningModeType.SERVER);

        int parsedPort = parsePort(port);
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection != null) {
            inboundConnection.setPort(parsedPort);
        } else {
            inboundConnection = new InboundConnection(parsedPort);
            config.setDefaultServerConnection(inboundConnection);
        }
    }

    private int parsePort(Integer portStr) {
        if (portStr == null) {
            throw new ParameterException("Port must be set, but was not specified");
        }
        if (portStr < 0 || portStr > 65535) {
            throw new ParameterException("Port must be in interval [0,65535], but is " + port);
        }
        return portStr;
    }
}
