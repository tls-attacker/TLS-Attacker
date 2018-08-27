/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.server;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ListDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.server.config.ServerCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        ServerCommandConfig config = new ServerCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            ListDelegate list = (ListDelegate) config.getDelegate(ListDelegate.class);
            if (list.isSet()) {
                list.plotListing();
                return;
            }

            Config tlsConfig = null;
            try {
                tlsConfig = config.createConfig();
                TlsServer server = new TlsServer();
                server.run(tlsConfig);
            } catch (ConfigurationException E) {
                LOGGER.warn("Encountered a ConfigurationException aborting. Try -debug for more info");
                LOGGER.debug(E);
                commander.usage();
            }
        } catch (ParameterException E) {
            LOGGER.warn("Could not parse provided parameters. Try -debug for more info");
            LOGGER.debug(E);
            commander.usage();
        }
    }
}
