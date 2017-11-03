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
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientDelegate extends Delegate {

    @Parameter(names = "-connect", required = true, description = "Who to connect to. Syntax: localhost:4433")
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

        config.setDefaulRunningMode(RunningModeType.CLIENT);

        if (host == null) {
            // Though host is a required parameter we can get here if
            // we call applyDelegate manually, e.g. in tests.
            throw new ParameterException("Could not parse provided host: " + host);
        }

        OutboundConnection con = config.getDefaultClientConnection();
        if (con == null) {
            con = new OutboundConnection();
            config.setDefaultClientConnection(con);
        }
        String[] parsedHost = host.split(":");
        switch (parsedHost.length) {
            case 1:
                con.setHostname(host);
                break;
            case 2:
                con.setHostname(parsedHost[0]);
                con.setPort(parsePort(parsedHost[1]));
                break;
            default:
                throw new ParameterException("Could not parse provided host: " + host);
        }
    }

    private int parsePort(String portStr) {
        int port = Integer.parseInt(portStr);
        if (port < 0 || port > 65535) {
            throw new ParameterException("port must be in interval [0,65535], but is " + port);
        }
        return port;
    }

}
