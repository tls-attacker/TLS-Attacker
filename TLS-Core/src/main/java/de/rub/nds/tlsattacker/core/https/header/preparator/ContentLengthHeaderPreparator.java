/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.preparator;

import de.rub.nds.tlsattacker.core.https.header.ContentLengthHeader;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ContentLengthHeaderPreparator extends Preparator<ContentLengthHeader> {

    private final ContentLengthHeader header;

    public ContentLengthHeaderPreparator(Chooser chooser, ContentLengthHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Content-Length");
        header.setLength(header.getConfigLength());
        header.setHeaderValue("" + header.getLength().getValue());
    }
}
