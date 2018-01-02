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
import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.attacks.config.delegate.AttackDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.LinkedList;
import java.util.List;

public class PskBruteForcerAttackServerCommandConfig extends AttackConfig {
    public static final String ATTACK_COMMAND = "pskbruteforcerserver";

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @Parameter(names = "-usePskTable", description = "Enables the use of the PskTable")
    private boolean usePskTable = false;
    @Parameter(names = "-useDheDowngrade", description = "Use the EdhPsk to Psk Downgrade")
    private boolean useDheDowngrade = false;
    @Parameter(names = "-useEcDheDowngrade", description = "Use the EcEdhPsk to Psk Downgrade")
    private boolean useEcDheDowngrade = false;

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            if (this.useDheDowngrade) {
                cipherSuites.add(CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
            } else if (this.useEcDheDowngrade) {
                cipherSuites.add(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA);
            } else {
                cipherSuites.add(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
            }
            config.setDefaultClientSupportedCiphersuites(cipherSuites);
        }
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        return config;
    }

    public PskBruteForcerAttackServerCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        attackDelegate = new AttackDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(attackDelegate);
    }

    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    public boolean getUsePskTable() {
        return usePskTable;
    }

    public boolean getDheDowngrade() {
        return useDheDowngrade;
    }

    public boolean getEcDheDowngrade() {
        return useEcDheDowngrade;
    }
}
