/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateStatusPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateStatusSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class CertificateStatusHandler extends HandshakeMessageHandler<CertificateStatusMessage> {
    public CertificateStatusHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public CertificateStatusParser getParser(byte[] message, int pointer) {
        return new CertificateStatusParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion(),
            tlsContext.getConfig());
    }

    @Override
    public CertificateStatusPreparator getPreparator(CertificateStatusMessage message) {
        return new CertificateStatusPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public CertificateStatusSerializer getSerializer(CertificateStatusMessage message) {
        return new CertificateStatusSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(CertificateStatusMessage message) {

    }
}
