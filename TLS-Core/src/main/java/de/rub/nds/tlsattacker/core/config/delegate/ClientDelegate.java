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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

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
        if (host != null) {
            String[] parsedHost = host.split(":");
            if (parsedHost.length == 1) {
                config.setHost(host);
            } else if (parsedHost.length == 2) {
                config.setHost(parsedHost[0]);
                config.setPort(Integer.parseInt(parsedHost[1]));
            } else {
                throw new ConfigurationException("Could not parse provided host: " + host);
            }
        }
        config.setDefaultConnectionEndType(ConnectionEndType.CLIENT);
    }

}
