/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.exceptions.InvalidChooserTypeException;
import de.rub.nds.tlsattacker.core.state.Context;

public class ChooserFactory {

    public static Chooser getChooser(ChooserType type, Context context, Config config) {
        switch (type) {
            case DEFAULT:
                return new DefaultChooser(context, config);
            case SMART_RECORD_SIZE:
                return new SmartRecordSizeChooser(context, config);
            default:
                throw new InvalidChooserTypeException("ChooserType \"" + type + "\" not supported");
        }
    }

    private ChooserFactory() {}
}
