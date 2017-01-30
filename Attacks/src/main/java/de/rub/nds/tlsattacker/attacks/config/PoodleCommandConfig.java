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

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class PoodleCommandConfig extends TLSDelegateConfig {

    public static final String ATTACK_COMMAND = "poodle";
    @ParametersDelegate
    private ClientDelegate clientDelegate;

    public PoodleCommandConfig() {
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
    }

}
