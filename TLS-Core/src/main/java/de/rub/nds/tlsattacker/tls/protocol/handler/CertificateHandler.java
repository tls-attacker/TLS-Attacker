/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.CertificateMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.util.JKSLoader;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;
import sun.security.rsa.RSAPublicKeyImpl;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateHandler extends HandshakeMessageHandler<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger(CertificateHandler.class);

    public CertificateHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    protected CertificateMessageParser getParser(byte[] message, int pointer) {
        return new CertificateMessageParser(pointer, message);
    }

    @Override
    protected Preparator getPreparator(CertificateMessage message) {
        return new CertificateMessagePreparator(tlsContext, message);
    }

    @Override
    protected Serializer getSerializer(CertificateMessage message) {
        return new CertificateMessageSerializer(message);
    }

    @Override
    protected void adjustTLSContext(CertificateMessage message) {
        Certificate cert = parseCertificate(message.getCertificatesLength().getValue(), message
                .getX509CertificateBytes().getValue());
        if (tlsContext.getTalkingConnectionEnd() == ConnectionEnd.CLIENT) {
            tlsContext.setClientCertificate(cert);
            tlsContext.setClientPublicKey(parsePublicKey(cert));
        } else {
            tlsContext.setServerCertificate(cert);
            tlsContext.setServerPublicKey(parsePublicKey(cert));

        }
    }

    private PublicKey parsePublicKey(Certificate cert) {
        try {
            X509CertificateObject certObj = new X509CertificateObject(cert.getCertificateAt(0));
            return certObj.getPublicKey();
        } catch (CertificateParsingException ex) {
            LOGGER.warn("Could extract public Key from Certificate!", ex);
            return null;
        }
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH), bytesToParse));
            return Certificate.parse(stream);
        } catch (IOException E) {
            LOGGER.warn("Could not parse Certificate bytes into Certificate object:"
                    + ArrayConverter.bytesToHexString(bytesToParse, false));
            return null;
        }
    }
}
