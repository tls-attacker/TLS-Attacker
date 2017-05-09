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
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EarlyCCSCommandConfig extends AttackConfig {
    public static final String ATTACK_COMMAND = "early_ccs";

    @ParametersDelegate
    private final ClientDelegate clientDelegate;
    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private final CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private final ProtocolVersionDelegate protocolVersionDelegate;

    public EarlyCCSCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
    }

    @Override
    public TlsConfig createConfig() {
        return super.createConfig();
    }

}
