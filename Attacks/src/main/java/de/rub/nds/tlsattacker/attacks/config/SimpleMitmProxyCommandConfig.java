/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CertificateDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.MitmDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class SimpleMitmProxyCommandConfig extends AttackConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    public static final String ATTACK_COMMAND = "simple_mitm_proxy";

    @ParametersDelegate
    private MitmDelegate mitmDelegate;

    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate
    private CertificateDelegate certificateDelegate;

    /**
     *
     * @param delegate
     */
    public SimpleMitmProxyCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        mitmDelegate = new MitmDelegate();
        ciphersuiteDelegate = new CipherSuiteDelegate();
        certificateDelegate = new CertificateDelegate();
        addDelegate(mitmDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(certificateDelegate);
    }

    /*
     * Always execute attack.
     */
    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return true;
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        return config;
    }

}
