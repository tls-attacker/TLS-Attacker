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
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientDelegate extends Delegate {

    @Parameter(names = "-connect", required = true, description = "who to connect to")
    private String host = null;

    public ClientDelegate() {
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    @Override
    public void applyDelegate(Config config) {
        if (host == null) {
            // Though host is a required parameter we can get here if
            // we call applyDelegate manually, e.g. in tests.
            throw new ParameterException("Could not parse provided host: " + host);
        }

        ClientConnectionEnd conEnd = new ClientConnectionEnd(Config.DEFAULT_CONNECTION_END_ALIAS);
        String[] parsedHost = host.split(":");
        switch (parsedHost.length) {
            case 1:
                conEnd.setHostname(host);
                conEnd.setPort(config.getConnectionEnd().getPort());
                break;
            case 2:
                conEnd.setHostname(parsedHost[0]);
                conEnd.setPort(parsePort(parsedHost[1]));
                break;
            default:
                throw new ParameterException("Could not parse provided host: " + host);
        }
        config.clearConnectionEnds();
        config.addConnectionEnd(conEnd);

    }

    private int parsePort(String portStr) {
        int port = Integer.parseInt(portStr);
        if (port < 0 || port > 65535) {
            throw new ParameterException("port must be in interval [0,65535], but is " + port);
        }
        return port;
    }

}
