/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls.handler;

import de.rub.nds.tlsattacker.core.dtls.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;

public class DtlsHandshakeMessageFragmentHandler extends Handler<DtlsHandshakeMessageFragment> {

    private TlsContext context;

    public DtlsHandshakeMessageFragmentHandler(TlsContext tlsContext) {
        super();
        this.context = tlsContext;
    }

    @Override
    public void adjustContext(DtlsHandshakeMessageFragment message) {}
}
