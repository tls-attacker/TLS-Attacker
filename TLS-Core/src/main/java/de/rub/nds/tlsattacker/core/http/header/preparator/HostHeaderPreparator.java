/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header.preparator;

import de.rub.nds.tlsattacker.core.http.header.HostHeader;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class HostHeaderPreparator extends Preparator<HostHeader> {

    private final HostHeader header;

    public HostHeaderPreparator(Chooser chooser, HostHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Host");
        header.setHeaderValue(chooser.getConnection().getHostname());
    }
}
