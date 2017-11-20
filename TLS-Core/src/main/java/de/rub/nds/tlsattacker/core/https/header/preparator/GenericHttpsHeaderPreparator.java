/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.preparator;

import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class GenericHttpsHeaderPreparator extends Preparator<GenericHttpsHeader> {

    private final GenericHttpsHeader header;

    public GenericHttpsHeaderPreparator(Chooser chooser, GenericHttpsHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName(header.getHeaderNameConfig());
        header.setHeaderValue(header.getHeaderValueConfig());
    }

}
