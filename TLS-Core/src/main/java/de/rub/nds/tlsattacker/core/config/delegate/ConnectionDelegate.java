/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class ConnectionDelegate extends Delegate {

    @Parameter(names = "-useIpV6", required = false, description = "Whether to use IPv6 or not.")
    private boolean useIpV6 = false;

    public ConnectionDelegate() {}

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        OutboundConnection connection = config.getDefaultClientConnection();
        if (connection != null) {
            connection.setUseIpv6(useIpV6);
            config.setDefaultClientConnection(connection);
        }
    }
}
