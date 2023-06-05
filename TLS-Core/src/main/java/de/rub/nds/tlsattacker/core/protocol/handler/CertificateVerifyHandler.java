/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;

/**
 * Handling of the CertificateVerify protocol message: <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.8">RFC 5246 Section 7.4.8</a>
 *
 * <p>The TLS spec as well as wireshark bring some nice confusions: - The TLS spec says the message
 * consists of only signature bytes - Wireshark says the message consists of the signature length
 * and signature bytes
 *
 * <p>In fact, the certificate message consists of the following fields: - signature algorithm (2
 * bytes) - signature length (2 bytes) - signature
 *
 * <p>This structure is of course prepended with the handshake message length, as obvious for every
 * handshake message.
 */
public class CertificateVerifyHandler extends HandshakeMessageHandler<CertificateVerifyMessage> {

    public CertificateVerifyHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(CertificateVerifyMessage message) {
        // Maybe check if we can verify signature and set boolean in context
        // //TODO
        // Don't adjust the TLSContext
    }
}
