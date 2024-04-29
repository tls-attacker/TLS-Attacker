/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class DataAttributePreparator extends StunAttributePreparator<DataAttribute> {

    public DataAttributePreparator(Chooser chooser, DataAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        byte[] data;
        if (getObject().getDataConfig() != null) {
            data = getObject().getDataConfig();
        } else {
            data = chooser.getIceChooser().getConfig().getDefaultData();
        }
        getObject().setData(data);
    }
}
