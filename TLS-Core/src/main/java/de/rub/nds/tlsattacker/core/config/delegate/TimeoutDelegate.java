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
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;

public class TimeoutDelegate extends Delegate {

    @Parameter(names = "-timeout", description = "Timeout for socket connection")
    private Integer timeout = null;

    public TimeoutDelegate() {
    }

    public Integer getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    @Override
    public void applyDelegate(Config config) {
        if (timeout == null) {
            return;
        }

        if (config.getDefaultClientConnection() == null) {
            config.setDefaultClientConnection(new OutboundConnection());
        }
        if (config.getDefaultServerConnection() == null) {
            config.setDefaultServerConnection(new InboundConnection());
        }
        config.getDefaultClientConnection().setTimeout(timeout);
        config.getDefaultServerConnection().setTimeout(timeout);
    }

}
