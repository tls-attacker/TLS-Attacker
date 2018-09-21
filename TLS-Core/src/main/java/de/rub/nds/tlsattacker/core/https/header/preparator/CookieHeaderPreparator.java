/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header.preparator;

import de.rub.nds.tlsattacker.core.https.header.CookieHeader;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.commons.lang3.StringUtils;

public class CookieHeaderPreparator extends Preparator<CookieHeader> {

    private final CookieHeader header;

    public CookieHeaderPreparator(Chooser chooser, CookieHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Cookie");
        String headerValue = StringUtils.join(chooser.getHttpsCookieName(), '=', chooser.getHttpsCookieValue());
        header.setHeaderValue(headerValue);
    }

}
