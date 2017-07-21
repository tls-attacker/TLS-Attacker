/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class AttackDelegate extends Delegate {

    @Parameter(names = "-executeAttack", description = "If this value is set the Attack is not only Tested, but also executed (WARNING)")
    private boolean executeAttack = false;

    public boolean isExecuteAttack() {
        return executeAttack;
    }

    public void setExecuteAttack(boolean executeAttack) {
        this.executeAttack = executeAttack;
    }

    public AttackDelegate() {
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
    }

}
