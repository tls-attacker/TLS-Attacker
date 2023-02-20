/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerHelloHandler extends ProtocolMessageHandler<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    private X509CertificateChain parseCertificate(int lengthBytes, byte[] bytesToParse) {
        LOGGER.debug("SSL2 lengthBytes:" + lengthBytes);
        LOGGER.debug("SSL2 bytesToParse:" + ArrayConverter.bytesToHexString(bytesToParse, false));

        try {
            byte[] concatenated =
                    ArrayConverter.concatenate(
                            ArrayConverter.intToBytes(
                                    lengthBytes + HandshakeByteLength.CERTIFICATES_LENGTH,
                                    HandshakeByteLength.CERTIFICATES_LENGTH),
                            ArrayConverter.intToBytes(
                                    lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH),
                            bytesToParse);
            LOGGER.debug(
                    "SSL2 concatenated:" + ArrayConverter.bytesToHexString(concatenated, false));
            ByteArrayInputStream stream = new ByteArrayInputStream(concatenated);
            return CertificateIo.readRawChain(
                    stream); // TODO This is not correct, we are not adjusting the x509 context
        } catch (IOException | IllegalArgumentException e) {
            LOGGER.warn(
                    "Could not parse Certificate bytes into Certificate object:\n"
                            + ArrayConverter.bytesToHexString(bytesToParse, false));
            LOGGER.debug(e);
            return null;
        }
    }

    @Override
    public void adjustContext(SSL2ServerHelloMessage message) {
        byte[] serverRandom = message.getSessionId().getValue();
        if (serverRandom != null) {
            tlsContext.setServerRandom(serverRandom);
        }
        X509CertificateChain certificateChain =
                parseCertificate(
                        message.getCertificateLength().getValue(),
                        message.getCertificate().getValue());
        LOGGER.debug("Setting ServerCertificate in Context");
        tlsContext.setServerCertificateChain(certificateChain);
    }
}
