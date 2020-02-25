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
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
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
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
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

    private CertificateType selectTypeInternally() {
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            return tlsContext.getChooser().getSelectedServerCertificateType();
        } else {
            return tlsContext.getChooser().getSelectedClientCertificateType();
        }
    }

    @Override
    public void adjustTLSContext(CertificateMessage message) {
        switch (selectTypeInternally()) {
            case OPEN_PGP:
                throw new UnsupportedOperationException("We do not support OpenPGP keys");
            case RAW_PUBLIC_KEY:
                LOGGER.debug("Adjusting context for RAW PUBLIC KEY ceritifate message");
                try {
                    // TODO Temporary parsing, we need to redo this once
                    // x509/asn1 attacker is integrated
                    ASN1InputStream asn1Stream = new ASN1InputStream(message.getCertificatesListBytes().getValue());
                    DLSequence dlSeq = (DLSequence) asn1Stream.readObject();
                    DLSequence identifier = (DLSequence) dlSeq.getObjectAt(0);
                    NamedGroup group = null;
                    ASN1ObjectIdentifier keyType = (ASN1ObjectIdentifier) identifier.getObjectAt(0);
                    if (keyType.getId().equals("1.2.840.10045.2.1")) {
                        ASN1ObjectIdentifier curveType = (ASN1ObjectIdentifier) identifier.getObjectAt(1);
                        if (curveType.getId().equals("1.2.840.10045.3.1.7")) {
                            group = NamedGroup.SECP256R1;
                        } else {
                            throw new UnsupportedOperationException(
                                    "We currently do only support secp256r1 public keys. Sorry...");
                        }
                        DERBitString publicKey = (DERBitString) dlSeq.getObjectAt(1);
                        byte[] pointBytes = publicKey.getBytes();
                        Point publicKeyPoint = PointFormatter.formatFromByteArray(group, pointBytes);
                        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
                            tlsContext.setServerEcPublicKey(publicKeyPoint); // TODO
                                                                             // this
                                                                             // needs
                                                                             // to
                                                                             // be
                                                                             // a
                                                                             // new
                                                                             // field
                                                                             // in
                                                                             // the
                                                                             // context
                        } else {
                            tlsContext.setClientEcPublicKey(publicKeyPoint); // TODO
                                                                             // this
                                                                             // needs
                                                                             // to
                                                                             // be
                                                                             // a
                                                                             // new
                                                                             // field
                                                                             // in
                                                                             // the
                                                                             // context
                        }
                    } else {
                        throw new UnsupportedOperationException(
                                "We currently do only support EC raw public keys. Sorry...");
                    }

                    asn1Stream.close();
                } catch (Exception E) {
                    LOGGER.warn("Could read RAW PublicKey. Not adjusting context", E);

                }
                break;
            case X509:
                LOGGER.debug("Adjusting context for x509 ceritifate message");
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
                    cert = parseCertificate(message.getCertificatesListLength().getValue(), message
                            .getCertificatesListBytes().getValue());
                }
                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                    LOGGER.debug("Setting ClientCertificate in Context");
                    tlsContext.setClientCertificate(cert);
                } else {
                    LOGGER.debug("Setting ServerCertificate in Context");
                    tlsContext.setServerCertificate(cert);
                }
                if (message.getCertificateKeyPair() != null) {
                    LOGGER.debug("Found a certificate key pair. Adjusting in context");
                    message.getCertificateKeyPair().adjustInContext(tlsContext,
                            tlsContext.getTalkingConnectionEndType());
                } else if (cert != null) {
                    if (cert.isEmpty()) {
                        LOGGER.debug("Certificate is empty - no adjustments");
                    } else {
                        LOGGER.debug("No CertificatekeyPair found, creating new one");
                        CertificateKeyPair pair = new CertificateKeyPair(cert);
                        message.setCertificateKeyPair(pair);
                        message.getCertificateKeyPair().adjustInContext(tlsContext,
                                tlsContext.getTalkingConnectionEndType());
                    }

                } else {
                    LOGGER.debug("Ceritificate not parseable - no adjustments");
                }

                if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
                    adjustExtensions(message);
                }
                break;
            default:
                throw new UnsupportedOperationException("Unsupported CertificateType!");
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
            LOGGER.warn(
                    "Could not parse Certificate bytes into Certificate object:"
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
