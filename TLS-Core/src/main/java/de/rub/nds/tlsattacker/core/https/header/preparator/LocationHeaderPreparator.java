/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.preparator;

import de.rub.nds.tlsattacker.core.https.header.LocationHeader;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class LocationHeaderPreparator extends Preparator<LocationHeader> {

    private final LocationHeader header;

    public LocationHeaderPreparator(Chooser chooser, LocationHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Location");
        header.setHeaderValue(chooser.getContext().getHttpContext().getLastRequestPath());
    }
}
