/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class CertificateStatusHandler extends HandshakeMessageHandler<CertificateStatusMessage> {
    public CertificateStatusHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(CertificateStatusMessage message) {

    }
}
