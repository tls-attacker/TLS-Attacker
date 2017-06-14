/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateHandler extends HandshakeMessageHandler<CertificateMessage> {

    public CertificateHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public CertificateMessageParser getParser(byte[] message, int pointer) {
        return new CertificateMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public CertificateMessagePreparator getPreparator(CertificateMessage message) {
        return new CertificateMessagePreparator(tlsContext, message);
    }

    @Override
    public CertificateMessageSerializer getSerializer(CertificateMessage message) {
        return new CertificateMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(CertificateMessage message) {
        Certificate cert;
        if (tlsContext.getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            cert = parseCertificate(message.getCertificatesListLength().getValue(), message.getCertificatesListBytes()
                    .getValue());
        } else {
            // cert = parseCertificate();
            cert = null;
        }
        if (tlsContext.getTalkingConnectionEnd() == ConnectionEnd.CLIENT) {
            LOGGER.debug("Setting ClientCertificate in Context");
            tlsContext.setClientCertificate(cert);
            if (cert != null) {
                LOGGER.debug("Setting ClientPublicKey in Context");
                tlsContext.setClientCertificatePublicKey(parsePublicKey(cert));
            }
        } else {
            LOGGER.debug("Setting ServerCertificate in Context");
            tlsContext.setServerCertificate(cert);
            if (cert != null) {
                LOGGER.debug("Setting ServerPublicKey in Context");
                tlsContext.setServerCertificatePublicKey(parsePublicKey(cert));
            }
        }
        if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            if (message.getExtensions() != null) {
                for (ExtensionMessage extension : message.getExtensions()) {
                    extension.getHandler(tlsContext).adjustTLSContext(extension);
                }
            }
        }
    }

    private PublicKey parsePublicKey(Certificate cert) {
        try {
            X509CertificateObject certObj = new X509CertificateObject(cert.getCertificateAt(0));
            return certObj.getPublicKey();
        } catch (CertificateParsingException ex) {
            LOGGER.warn("Could extract public Key from Certificate!");
            LOGGER.debug(ex);
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

    private byte[] adjustCertificateExtensions(CertificateMessage message) {
        List<CertificateEntry> certificateEntryList = new LinkedList<>();
        for (CertificatePair pair : message.getCertificatesList()) {
            // Parse extensions
            List<ExtensionMessage> extensionMessages = new LinkedList<>();
            int pointer = 0;
            while (pointer < pair.getExtensionsLength().getValue()) {
            ExtensionParser parser = ExtensionParserFactory.getExtensionParser(pair.getExtensions().getValue(), pointer);
            extensionMessages.add(parser.parse());
            pointer = parser.getPointer();
            }
            // Parse certificate
            // ksEntryList.add(new CertificateEntry(null, extensionMessages);
        }
        return null;
    }
}
