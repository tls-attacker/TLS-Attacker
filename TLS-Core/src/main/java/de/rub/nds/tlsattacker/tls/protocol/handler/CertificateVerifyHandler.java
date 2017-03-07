/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.CertificateVerifyMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.CertificateVerifyMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.CertificateVerifyMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Handling of the CertificateVerify protocol message:
 * http://tools.ietf.org/html/rfc5246#section-7.4.8
 * 
 * The TLS spec as well as wireshark bring some nice confusions: - The TLS spec
 * says the message consists of only signature bytes - Wireshark says the
 * message consists of the signature length and signature bytes
 * 
 * In fact, the certificate message consists of the following fields: -
 * signature algorithm (2 bytes) - signature length (2 bytes) - signature
 * 
 * This structure is of course prepended with the handshake message length, as
 * obvious for every handshake message.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <Message>
 */
public class CertificateVerifyHandler extends HandshakeMessageHandler<CertificateVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger(CertificateVerifyHandler.class);

    public CertificateVerifyHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    protected CertificateVerifyMessageParser getParser(byte[] message, int pointer) {
        return new CertificateVerifyMessageParser(pointer, message);
    }

    @Override
    protected Preparator getPreparator(CertificateVerifyMessage message) {
        return new CertificateVerifyMessagePreparator(tlsContext, message);
    }

    @Override
    protected Serializer getSerializer(CertificateVerifyMessage message) {
        return new CertificateVerifyMessageSerializer(message);
    }

    @Override
    protected void adjustTLSContext(CertificateVerifyMessage message) {
        // Maybe check if we can verify signature and set boolean in context
        // //TODO
        // Dont adjust the TLSContext
    }
}
