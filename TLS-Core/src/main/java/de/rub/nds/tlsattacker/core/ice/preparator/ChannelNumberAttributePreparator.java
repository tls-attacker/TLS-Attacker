/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.preparator;

import de.rub.nds.tlsattacker.core.ice.model.ChannelNumberAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ChannelNumberAttributePreparator
        extends StunAttributePreparator<ChannelNumberAttribute> {

    public ChannelNumberAttributePreparator(Chooser chooser, ChannelNumberAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        // Prefer explicitly configured value if present
        if (getObject().getChannelNumber() == null
                || getObject().getChannelNumber().getValue() == null) {
            Integer cfg = getObject().getChannelNumberConfig();
            if (cfg != null) {
                getObject().setChannelNumber(cfg);
            } else {
                // If no config provided, use a default TURN channel number from context if
                // available.
                // There is no dedicated field in context; leave unset (serializer will still
                // handle) or set a common default.
                // Using a safe default in the valid range (0x4000)
                getObject().setChannelNumber(0x4000);
            }
        }
        if (getObject().getRffu() == null || getObject().getRffu().getValue() == null) {
            // RFFU must be 0 on transmission
            getObject().setRffu(0);
        }
    }
}
