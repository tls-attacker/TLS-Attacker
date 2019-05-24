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
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;

/**
 *
 */
public class EarlyCCSCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "early_ccs";

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    /**
     *
     * @param delegate
     */
    public EarlyCCSCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(starttlsDelegate);
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
        config.setAddRenegotiationInfoExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setQuickReceive(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setEarlyStop(true);
        boolean containsEc = false;
        for (CipherSuite suite : config.getDefaultClientSupportedCiphersuites()) {
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
