/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EarlyCCSCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "early_ccs";
}
