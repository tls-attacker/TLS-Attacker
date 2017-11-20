/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.MitmDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerCertificateDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SimpleMitmProxyCommandConfig extends AttackConfig {

    protected static final Logger LOGGER = LogManager.getLogger(SimpleMitmProxyCommandConfig.class);
    public static final String ATTACK_COMMAND = "simple_mitm_proxy";

    @ParametersDelegate
    private MitmDelegate mitmDelegate;

    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate
    private ServerCertificateDelegate serverCertificateDelegate;

    public SimpleMitmProxyCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        mitmDelegate = new MitmDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        serverCertificateDelegate = new ServerCertificateDelegate();
        addDelegate(mitmDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(serverCertificateDelegate);
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
