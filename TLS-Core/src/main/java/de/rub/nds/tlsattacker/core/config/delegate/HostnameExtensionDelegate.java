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

/**
 *

 */
public class HostnameExtensionDelegate extends Delegate {

    @Parameter(names = "-server_name", description = "Servername for HostName TLS extension.")
    private String sniHostname = null;

    public HostnameExtensionDelegate() {
    }

    public String getSniHostname() {
        return sniHostname;
    }

    public void setSniHostname(String sniHostname) {
        this.sniHostname = sniHostname;
    }

    @Override
    public void applyDelegate(Config config) {
        if (sniHostname != null) {
            config.setAddServerNameIndicationExtension(true);
            config.setSniHostname(sniHostname);
        }
    }
}
