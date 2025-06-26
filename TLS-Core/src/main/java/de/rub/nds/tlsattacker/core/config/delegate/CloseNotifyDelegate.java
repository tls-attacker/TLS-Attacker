/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;

public class CloseNotifyDelegate extends Delegate {

    @Parameter(
            names = "-close_notify",
            arity = 1,
            description = "Send close notify alert when finishing (overrides config file setting)")
    private Boolean finishWithCloseNotify = null;

    public CloseNotifyDelegate() {}

    public Boolean getFinishWithCloseNotify() {
        return finishWithCloseNotify;
    }

    public void setFinishWithCloseNotify(Boolean finishWithCloseNotify) {
        this.finishWithCloseNotify = finishWithCloseNotify;
    }

    @Override
    public void applyDelegate(Config config) {
        if (finishWithCloseNotify != null) {
            config.setFinishWithCloseNotify(finishWithCloseNotify);
        }
    }
}
