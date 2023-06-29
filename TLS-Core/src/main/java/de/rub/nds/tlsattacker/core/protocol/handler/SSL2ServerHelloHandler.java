/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

public class SSL2ServerHelloHandler extends ProtocolMessageHandler<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        LOGGER.debug("SSL2 lengthBytes:" + lengthBytes);
        LOGGER.debug("SSL2 bytesToParse: {}", bytesToParse);

        try {
            byte[] concatenated =
                    ArrayConverter.concatenate(
                            ArrayConverter.intToBytes(
                                    lengthBytes + HandshakeByteLength.CERTIFICATES_LENGTH,
                                    HandshakeByteLength.CERTIFICATES_LENGTH),
                            ArrayConverter.intToBytes(
                                    lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH),
                            bytesToParse);
            LOGGER.debug("SSL2 concatenated: {}", concatenated);
            ByteArrayInputStream stream = new ByteArrayInputStream(concatenated);
            return Certificate.parse(stream);
        } catch (IOException | IllegalArgumentException e) {
            LOGGER.warn(
                    "Could not parse Certificate bytes into Certificate object:\n{}", bytesToParse);
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
        Certificate cert =
                parseCertificate(
                        message.getCertificateLength().getValue(),
                        message.getCertificate().getValue());
        LOGGER.debug("Setting ServerCertificate in Context");
        tlsContext.setServerCertificate(cert);

        if (cert == null || !CertificateUtils.hasRSAParameters(cert)) {
            LOGGER.error("Cannot parse Certificate from SSL2ServerHello");
        } else {
            LOGGER.debug("Adjusting RSA PublicKey");
            try {
                tlsContext.setServerRSAPublicKey(CertificateUtils.extractRSAPublicKey(cert));
                tlsContext.setServerRSAModulus(CertificateUtils.extractRSAModulus(cert));
            } catch (IOException e) {
                throw new AdjustmentException(
                        "Could not adjust PublicKey Information from Certificate", e);
            }
        }
    }
}
