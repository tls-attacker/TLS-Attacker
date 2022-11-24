/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Objects;

public class InterfaceDelegate extends Delegate {

    @Parameter(names = "-interface", description = "Name of the network interface to use")
    private String networkInterface = "";

    public InterfaceDelegate() {}

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        config.setNetworkInterface(networkInterface);

        NetworkInterface networkInterface = null;
        if (!Objects.equals(this.networkInterface, "")) {
            try {
                networkInterface = NetworkInterface.getByName(this.networkInterface);
            } catch (SocketException e) {
                LOGGER.warn(
                        "Could not attach to interface " + this.networkInterface + "with error: ",
                        e);
            }
        }
        if (networkInterface == null) {
            LOGGER.warn(
                    "Network interface "
                            + this.networkInterface
                            + " not found. Defaulting to automatic interface "
                            + "selection");
            return;
        }
        config.getDefaultClientConnection().setNetworkInterface(networkInterface);
        config.getDefaultServerConnection().setNetworkInterface(networkInterface);
    }
}
