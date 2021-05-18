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
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class PoodleCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "poodle";
    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;
    @ParametersDelegate
    private CipherSuiteDelegate cipherSuiteDelegate;

    /**
     *
     * @param delegate
     */
    public PoodleCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        starttlsDelegate = new StarttlsDelegate();
        cipherSuiteDelegate = new CipherSuiteDelegate();
        addDelegate(clientDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(cipherSuiteDelegate);
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return false;
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (cipherSuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isCBC() && !suite.isPsk() && !suite.isSrp()) {
                    cipherSuites.add(suite);
                }
            }
            config.setDefaultClientSupportedCipherSuites(cipherSuites);
        }
        for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
            if (!suite.isCBC()) {
                throw new ConfigurationException("This attack only works with CBC Cipher suites");
            }
        }
        config.setStopActionsAfterFatal(true);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setQuickReceive(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setEarlyStop(true);
        boolean containsEc = false;
        for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
            KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
            if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.name().toUpperCase().contains("EC")) {
                containsEc = true;
                break;
            }
        }
        config.setAddECPointFormatExtension(containsEc);
        config.setAddEllipticCurveExtension(containsEc);
        return config;
    }
}
