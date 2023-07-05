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
import de.rub.nds.tlsattacker.core.state.Context;

public class SmartRecordSizeChooser extends DefaultChooser {

    SmartRecordSizeChooser(Context context, Config config) {
        super(context, config);
    }

    @Override
    public Integer getOutboundMaxRecordDataSize() {
        if (config.getEnforcedMaxRecordData() != null) {
            return config.getEnforcedMaxRecordData();
        }
        int defaultMax = config.getDefaultMaxRecordData();
        int chooserMax = super.getOutboundMaxRecordDataSize();

        return Math.min(defaultMax, chooserMax);
    }
}
