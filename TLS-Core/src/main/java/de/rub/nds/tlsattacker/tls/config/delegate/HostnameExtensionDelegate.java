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

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HostnameExtensionDelegate extends Delegate {

    @Parameter(names = "-server_name", description = "Servername for HostName TLS extension.")
    private String sniHostname;
    @Parameter(names = "-servername_fatal", description = "On mismatch in the server name the server sends a fatal "
            + "alert")
    private boolean serverNameFatal;

    public HostnameExtensionDelegate() {
    }

    public String getSniHostname() {
        return sniHostname;
    }

    public void setSniHostname(String sniHostname) {
        this.sniHostname = sniHostname;
    }

    public boolean isServerNameFatal() {
        return serverNameFatal;
    }

    public void setServerNameFatal(boolean serverNameFatal) {
        this.serverNameFatal = serverNameFatal;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        config.setSniHostname(sniHostname);
        config.setSniHostnameFatal(serverNameFatal);
    }
}
