/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

public class SSL2ServerHelloHandler extends HandshakeMessageHandler<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerHelloHandler(TlsContext context) {
        super(context);
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        LOGGER.debug("SSL2 lengthBytes:" + lengthBytes);
        LOGGER.debug("SSL2 bytesToParse:" + ArrayConverter.bytesToHexString(bytesToParse, false));

        try {
            byte[] concatenated = ArrayConverter.concatenate(
                ArrayConverter.intToBytes(lengthBytes + HandshakeByteLength.CERTIFICATES_LENGTH,
                    HandshakeByteLength.CERTIFICATES_LENGTH),
                ArrayConverter.intToBytes(lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH), bytesToParse);
            LOGGER.debug("SSL2 concatenated:" + ArrayConverter.bytesToHexString(concatenated, false));
            ByteArrayInputStream stream = new ByteArrayInputStream(concatenated);
            return Certificate.parse(stream);
        } catch (IOException | IllegalArgumentException e) {
            LOGGER.warn("Could not parse Certificate bytes into Certificate object:\n"
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
        Certificate cert =
            parseCertificate(message.getCertificateLength().getValue(), message.getCertificate().getValue());
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
                throw new AdjustmentException("Could not adjust PublicKey Information from Certificate", e);
            }
        }
    }
}
