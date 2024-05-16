/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.preparator;

import de.rub.nds.tlsattacker.core.ice.model.UnknownAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class UnknownAttributePreparator extends StunAttributePreparator<UnknownAttribute> {

    public UnknownAttributePreparator(Chooser chooser, UnknownAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        getObject().setUnknownContent(new byte[0]);
    }
}
