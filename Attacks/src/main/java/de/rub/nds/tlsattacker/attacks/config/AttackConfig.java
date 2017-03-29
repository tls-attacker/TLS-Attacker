/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;

/**
 *
 * @author robert
 */
public class AttackConfig extends TLSDelegateConfig {

    @Parameter(names = "-executeAttack", description = "If this value is set the Attack is not only Tested, but also executed (WARNING)")
    private boolean executeAttack = false;

    public AttackConfig(GeneralDelegate delegate) {
        super(delegate);
    }

    public boolean isExecuteAttack() {
        return executeAttack;
    }

    public void setExecuteAttack(boolean executeAttack) {
        this.executeAttack = executeAttack;
    }
}
