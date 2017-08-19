/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.MitmDelegate;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class SimpleMitmProxyCommandConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "simple_mitm_proxy";

    @Parameter(names = "-server_certificate", description = "Path to the server's private certificate file (pem)")
    private String serverCertPath;

    @ParametersDelegate
    private final MitmDelegate mitmDelegate;

    public SimpleMitmProxyCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        mitmDelegate = new MitmDelegate();
        addDelegate(mitmDelegate);
    }

    public String getServerCertPath() {
        return serverCertPath;
    }

    public void setServerCertPath(String serverCertPath) {
        this.serverCertPath = serverCertPath;
    }

    /*
     * Always execute attack.
     */
    @Override
    public boolean isExecuteAttack() {
        return true;
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        return config;
    }
}
