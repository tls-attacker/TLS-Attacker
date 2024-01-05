/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl.DataContainerFilters.Tls;

import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.layer.DataContainerFilter;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;

public class WarningAlertFilter extends DataContainerFilter {

    @Override
    public boolean filterApplies(DataContainer container) {
        if (container.getClass().equals(AlertMessage.class)) {
            AlertMessage alert = (AlertMessage) container;
            return alert.getLevel().getValue() == AlertLevel.WARNING.getValue();
        }
        return false;
    }
}
