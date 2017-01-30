/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Cve20162107CommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "cve20162107";

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    public Cve20162107CommandConfig() {
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
    }

    @Override
    public TlsConfig createConfig() {
        TlsConfig config = super.createConfig();
        config.setSupportedCiphersuites(new LinkedList<CipherSuite>()); // TODO
        // really?
        config.setProtocolVersion(null); // TODO really?
        return config;
    }
}
