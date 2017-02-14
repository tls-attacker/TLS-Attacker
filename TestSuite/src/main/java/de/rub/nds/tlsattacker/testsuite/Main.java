/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testsuite;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.testsuite.config.ServerTestSuiteConfig;
import de.rub.nds.tlsattacker.testsuite.impl.ServerTestSuite;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Main {

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        ServerTestSuiteConfig stconfig = new ServerTestSuiteConfig(new GeneralDelegate());
        JCommander jc = new JCommander(stconfig);
        jc.parse(args);

        if (stconfig.getGeneralDelegate().isHelp() || jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }
        // TODO Probably not needed anymore
        switch (jc.getParsedCommand()) {
            case ServerTestSuiteConfig.COMMAND:
                ServerTestSuite st = new ServerTestSuite(stconfig);
                st.startTests();
                return;

            default:
                throw new ConfigurationException("No command found");
        }

    }
}
