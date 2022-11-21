/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https.header;

import de.rub.nds.tlsattacker.core.https.header.preparator.HostHeaderPreparator;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class HostHeader extends HttpsHeader {

    public HostHeader() {
    }

    @Override
    public HostHeaderPreparator getPreparator(Chooser chooser) {
        return new HostHeaderPreparator(chooser, this);
    }
}
