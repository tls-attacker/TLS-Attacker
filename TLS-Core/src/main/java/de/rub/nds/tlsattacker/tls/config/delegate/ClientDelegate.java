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
import de.rub.nds.tlsattacker.transport.ConnectionEnd;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientDelegate extends Delegate {
    @Parameter(names = "-connect", description = "who to connect to")
    private String host = "localhost:4433";

    public ClientDelegate() {
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        config.setHost(host);
        config.setMyConnectionEnd(ConnectionEnd.CLIENT);
    }

}
