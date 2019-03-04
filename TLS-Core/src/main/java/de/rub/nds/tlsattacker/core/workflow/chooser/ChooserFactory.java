/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.exceptions.InvalidChooserTypeException;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ChooserFactory {

    public static Chooser getChooser(ChooserType type, TlsContext context, Config config) {
        switch (type) {
            case DEFAULT:
                return new DefaultChooser(context, config);
            default:
                throw new InvalidChooserTypeException("ChooserType \"" + type + "\" not supported");
        }
    }

    private ChooserFactory() {
    }
}
