/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header;

import de.rub.nds.tlsattacker.core.https.header.preparator.ExpiresHeaderPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ExpiresHeader extends HttpsHeader {

    public ExpiresHeader() {
    }

    @Override
    public Preparator getPreparator(Chooser chooser) {
        return new ExpiresHeaderPreparator(chooser, this);
    }

}
