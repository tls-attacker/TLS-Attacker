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

        TestServerConfig config = new TestServerConfig();

        JCommander jc = new JCommander(config);

        jc.parse(args);

        if (config.getGeneralDelegate().isHelp()) {
            jc.usage();
            return;
        }
        TestTLSServer st = new TestTLSServer(config);
        st.startTests();
    }
}
