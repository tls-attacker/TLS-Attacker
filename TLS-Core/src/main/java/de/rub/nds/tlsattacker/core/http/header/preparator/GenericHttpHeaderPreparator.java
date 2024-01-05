/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header.preparator;

import de.rub.nds.tlsattacker.core.http.header.GenericHttpHeader;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class GenericHttpHeaderPreparator extends Preparator<GenericHttpHeader> {

    private final GenericHttpHeader header;

    public GenericHttpHeaderPreparator(Chooser chooser, GenericHttpHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName(header.getHeaderNameConfig());
        header.setHeaderValue(header.getHeaderValueConfig());
    }
}
