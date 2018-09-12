/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateMessageHandler extends HandshakeMessageHandler<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public CertificateMessageParser getParser(byte[] message, int pointer) {
        return new CertificateMessageParser(pointer, message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public CertificateMessagePreparator getPreparator(CertificateMessage message) {
        return new CertificateMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public CertificateMessageSerializer getSerializer(CertificateMessage message) {
        return new CertificateMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(CertificateMessage message) {
        Certificate cert;
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            int certificatesLength = 0;
            try {
                for (CertificatePair pair : message.getCertificatesList()) {
                    stream.write(ArrayConverter.intToBytes(pair.getCertificateLength().getValue(),
                            HandshakeByteLength.CERTIFICATE_LENGTH));
                    stream.write(pair.getCertificate().getValue());
                    certificatesLength += pair.getCertificateLength().getValue()
                            + HandshakeByteLength.CERTIFICATE_LENGTH;
                }
            } catch (IOException ex) {
                throw new AdjustmentException("Could not concatenate certificates bytes", ex);
            }
            cert = parseCertificate(certificatesLength, stream.toByteArray());
        } else {
            cert = parseCertificate(message.getCertificatesListLength().getValue(), message.getCertificatesListBytes()
                    .getValue());
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            LOGGER.debug("Setting ClientCertificate in Context");
            tlsContext.setClientCertificate(cert);
        } else {
            LOGGER.debug("Setting ServerCertificate in Context");
            tlsContext.setServerCertificate(cert);
        }
        if (cert != null) {
            if (cert.getLength() == 0) {
                LOGGER.warn("Received empty Certificate Message");
            } else {
                CustomPublicKey customPublicKey = CertificateUtils.parseCustomPublicKey(CertificateUtils
                        .parsePublicKey(cert));
                customPublicKey.adjustInContext(tlsContext, tlsContext.getTalkingConnectionEndType());
            }
        } else {
            LOGGER.warn("Not adjusting Certificate public key - unparseable Certificate");
        }
        if (message.getCertificateKeyPair() != null) {
            message.getCertificateKeyPair().adjustInContext(tlsContext, tlsContext.getTalkingConnectionEndType());
        }
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            adjustExtensions(message);
        }
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(lengthBytes, HandshakeByteLength.CERTIFICATES_LENGTH), bytesToParse));
            return Certificate.parse(stream);
        } catch (Exception E) {
            // This could really be anything. From classCast exception to
            // Arrayindexoutofbounds
            LOGGER.warn("Could not parse Certificate bytes into Certificate object:"
                    + ArrayConverter.bytesToHexString(bytesToParse, false), E);
            LOGGER.debug(E);
            return null;
        }
    }

    private void adjustExtensions(CertificateMessage message) {
        if (message.getCertificatesListAsEntry() != null) {
            for (CertificateEntry entry : message.getCertificatesListAsEntry()) {
                if (entry.getExtensions() != null) {
                    for (ExtensionMessage extension : entry.getExtensions()) {
                        HandshakeMessageType handshakeMessageType = HandshakeMessageType.CERTIFICATE;
                        if (extension instanceof HRRKeyShareExtensionMessage) { // TODO
                            // fix
                            // design
                            // flaw
                            handshakeMessageType = HandshakeMessageType.HELLO_RETRY_REQUEST;
                        }
                        ExtensionHandler handler = HandlerFactory.getExtensionHandler(tlsContext,
                                extension.getExtensionTypeConstant(), handshakeMessageType);
                        handler.adjustTLSContext(extension);
                    }
                }
            }
        }
    }
}
