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
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.core.config.TlsConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PoodleCommandConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "poodle";
    @ParametersDelegate
    private final ClientDelegate clientDelegate;
    @ParametersDelegate
    private final HostnameExtensionDelegate hostnameExtensionDelegate;

    public PoodleCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
    }

    @Override
    public TlsConfig createConfig() {
        return super.createConfig();
    }

}
