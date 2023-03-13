/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;

public class CertificateMessageHandler extends HandshakeMessageHandler<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    private CertificateType selectTypeInternally() {
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            return tlsContext.getChooser().getSelectedServerCertificateType();
        } else {
            return tlsContext.getChooser().getSelectedClientCertificateType();
        }
    }

    @Override
    public void adjustContext(CertificateMessage message) {
        switch (selectTypeInternally()) {
            case OPEN_PGP:
                throw new UnsupportedOperationException("We do not support OpenPGP keys");
            case RAW_PUBLIC_KEY:
                LOGGER.debug("Adjusting context for RAW PUBLIC KEY certificate message");
                try (ASN1InputStream asn1Stream =
                        new ASN1InputStream(message.getCertificatesListBytes().getValue())) {
                    // TODO Temporary parsing, we need to redo this once
                    // x509/asn1 attacker is integrated
                    DLSequence dlSeq = (DLSequence) asn1Stream.readObject();
                    DLSequence identifier = (DLSequence) dlSeq.getObjectAt(0);
                    NamedGroup group;
                    ASN1ObjectIdentifier keyType = (ASN1ObjectIdentifier) identifier.getObjectAt(0);
                    if (keyType.getId().equals("1.2.840.10045.2.1")) {
                        ASN1ObjectIdentifier curveType =
                                (ASN1ObjectIdentifier) identifier.getObjectAt(1);
                        if (curveType.getId().equals("1.2.840.10045.3.1.7")) {
                            group = NamedGroup.SECP256R1;
                        } else {
                            throw new UnsupportedOperationException(
                                    "We currently do only support secp256r1 public keys. Sorry...");
                        }
                        DERBitString publicKey = (DERBitString) dlSeq.getObjectAt(1);
                        byte[] pointBytes = publicKey.getBytes();
                        Point publicKeyPoint =
                                PointFormatter.formatFromByteArray(
                                        (NamedEllipticCurveParameters) group.getGroupParameters(),
                                        pointBytes);
                        // This uses the x509 context, its technically not correct but for usability
                        // its beneficial
                        tlsContext.getTalkingX509Context().setSubjectEcPublicKey(publicKeyPoint);

                    } else {
                        throw new UnsupportedOperationException(
                                "We currently do only support EC raw public keys. Sorry...");
                    }
                } catch (Exception e) {
                    LOGGER.warn("Could read RAW PublicKey. Not adjusting context", e);
                }
                break;
            case X509:
                LOGGER.debug("Adjusting context for x509 certificate message");
                X509CertificateChain certificateChain = new X509CertificateChain();
                List<CertificateEntry> certificateEntryList = message.getCertificateEntryList();
                for (CertificateEntry entry : certificateEntryList) {
                    X509Certificate x509certificate = entry.getX509certificate();
                    if (x509certificate != null) {
                        certificateChain.addCertificate(x509certificate);
                    } else {
                        LOGGER.warn("Unparseable certificate entry in chain. Skipping in context");
                    }
                }

                if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                    LOGGER.debug("Setting ClientCertificateChain in Context");
                    tlsContext.setClientCertificateChain(certificateChain);
                } else {
                    LOGGER.debug("Setting ServerCertificateChain in Context");
                    tlsContext.setServerCertificateChain(certificateChain);
                }
                if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
                    adjustCertExtensions(message);
                }
                break;

            default:
                throw new UnsupportedOperationException("Unsupported CertificateType!");
        }
    }

    private void adjustCertExtensions(CertificateMessage certificateMessage) {
        for (CertificateEntry pair : certificateMessage.getCertificateEntryList()) {
            for (ExtensionMessage extensionMessage : pair.getExtensionList()) {
                extensionMessage.getHandler(tlsContext).adjustContext(extensionMessage);
            }
        }
    }

    @Override
    public void adjustContextBeforeParse(CertificateMessage message) {
        tlsContext.setTalkingX509Context(new X509Context());
    }
}
