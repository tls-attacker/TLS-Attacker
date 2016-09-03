/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.impl.TestTLSServer;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
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

        GeneralConfig generalConfig = new GeneralConfig();
        JCommander jc = new JCommander(generalConfig);

        TestServerConfig config = new TestServerConfig();
        jc.addCommand(TestServerConfig.COMMAND, config);

        jc.parse(args);

        if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }

        switch (jc.getParsedCommand()) {
            case TestServerConfig.COMMAND:
                TestTLSServer st = new TestTLSServer(config, generalConfig);
                st.startTests();
                return;

            default:
                throw new ConfigurationException("No command found");
        }

    }
}
