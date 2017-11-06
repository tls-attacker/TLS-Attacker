/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.mitm.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.mitm.config.MitmCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *

 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger(Main.class);

    public static void main(String[] args) {

        MitmCommandConfig config = new MitmCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        Exception ex = null;
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            Config tlsConfig = null;
            try {
                LOGGER.debug("Creating and launching mitm.");
                tlsConfig = config.createConfig();
                TlsMitm mitm = new TlsMitm();
                mitm.run(tlsConfig);
            } catch (ConfigurationException E) {
                LOGGER.info("Encountered a ConfigurationException aborting. " + "Try -debug for more details.");
                LOGGER.debug(E);
            }
        } catch (ParameterException E) {
            LOGGER.info("Could not parse provided parameters. " + "Try -debug for more details.");
            LOGGER.debug(E);
            commander.usage();
            ex = E;
        }
    }

}
