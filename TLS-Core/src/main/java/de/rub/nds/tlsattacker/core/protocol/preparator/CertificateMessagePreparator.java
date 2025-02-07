/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.cert.CertificateEntryPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.cert.CertificatePairSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import de.rub.nds.x509attacker.x509.X509CertificateChainBuilder;
import de.rub.nds.x509attacker.x509.X509ChainCreationResult;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;

public class CertificateMessagePreparator extends HandshakeMessagePreparator<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateMessage msg;

    public CertificateMessagePreparator(Chooser chooser, CertificateMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing CertificateMessage");
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            prepareRequestContext(msg);
            prepareRequestContextLength(msg);
        }
        prepareCertificateListBytes(msg);
    }

    private CertificateType selectTypeInternally() {
        if (chooser.getContext().getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            return chooser.getSelectedServerCertificateType();
        } else {
            return chooser.getSelectedClientCertificateType();
        }
    }

    private void prepareCertificateListBytes(CertificateMessage msg) {
        switch (selectTypeInternally()) {
            case OPEN_PGP:
                throw new UnsupportedOperationException("We do not support OpenPGP keys");
            case RAW_PUBLIC_KEY:
                LOGGER.debug("Adjusting context for RAW PUBLIC KEY certificate message");
                try {
                    // We currently only support this extension only very
                    // limited. Only secp256r1 is supported.
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    ASN1OutputStream asn1OutputStream =
                            ASN1OutputStream.create(byteArrayOutputStream);
                    Point ecPointToEncode =
                            chooser.getContext()
                                    .getTlsContext()
                                    .getTalkingX509Context()
                                    .getSubjectEcPublicKey();
                    // TODO this needs to be adjusted for different curves
                    asn1OutputStream.writeObject(
                            new DLSequence(
                                    new ASN1Encodable[] {
                                        new DLSequence(
                                                new ASN1Encodable[] {
                                                    new ASN1ObjectIdentifier("1.2.840.10045.2.1"),
                                                    new ASN1ObjectIdentifier("1.2.840.10045.3.1.7")
                                                }),
                                        new DERBitString(
                                                PointFormatter.formatToByteArray(
                                                        NamedEllipticCurveParameters.SECP256R1,
                                                        ecPointToEncode,
                                                        PointFormat.UNCOMPRESSED))
                                    }));
                    asn1OutputStream.flush();
                    msg.setCertificatesListBytes(byteArrayOutputStream.toByteArray());
                    msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
                } catch (Exception e) {
                    LOGGER.warn("Could write RAW PublicKey. Not writing anything", e);
                    msg.setCertificatesListBytes(new byte[0]);
                    msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
                }
                break;

            case X509:
                List<CertificateEntry> entryList = msg.getCertificateEntryList();
                if (chooser.getConfig().getDefaultExplicitCertificateChain() == null) {
                    if (entryList == null) {
                        if (chooser.getConfig().getAutoAdjustCertificate()) {
                            X509PublicKeyType[] certificateKeyTypes =
                                    AlgorithmResolver.getSuiteableLeafCertificateKeyType(
                                            chooser.getSelectedCipherSuite());
                            if (certificateKeyTypes != null) {
                                autoSelectCertificateKeyType(certificateKeyTypes);
                            } else {
                                LOGGER.warn(
                                        "Could not adjust public key in certificate to fit cipher suite");
                            }
                        }
                        // There is no certificate list in the message, this means we need to auto
                        // create one
                        LOGGER.debug("Building new certificate chain");
                        X509CertificateChainBuilder builder = new X509CertificateChainBuilder();
                        X509ChainCreationResult chainResult =
                                builder.buildChain(chooser.getConfig().getCertificateChainConfig());
                        chooser.getContext()
                                .getTlsContext()
                                .setTalkingX509Context(chainResult.getContext());
                        entryList = new LinkedList<>();
                        for (X509Certificate certificate :
                                chainResult.getCertificateChain().getCertificateList()) {
                            entryList.add(new CertificateEntry(certificate));
                        }
                        msg.setCertificateEntryList(entryList);
                    } else {
                        preparePredefinedCerts(entryList);
                    }
                    prepareFromEntryList(msg);
                } else {
                    entryList = new LinkedList<>();
                    for (CertificateBytes certificateBytes :
                            chooser.getConfig().getDefaultExplicitCertificateChain()) {
                        CertificateEntry entry = new CertificateEntry(certificateBytes.getBytes());
                        entryList.add(entry);
                    }
                    msg.setCertificateEntryList(entryList);
                    prepareFromEntryList(msg);
                }
                LOGGER.debug(
                        "CertificatesListBytes: {}", msg.getCertificatesListBytes().getValue());
                break;

            default:
                throw new UnsupportedOperationException("Unsupported CertificateType");
        }
    }

    private void autoSelectCertificateKeyType(X509PublicKeyType[] certificateKeyTypes) {
        if (chooser.getConfig().getAutoAdjustSignatureAndHashAlgorithm()) {
            chooser.getConfig()
                    .getCertificateChainConfig()
                    .get(0)
                    .setPublicKeyType(certificateKeyTypes[0]);
        } else {
            for (X509PublicKeyType certKeyType : certificateKeyTypes) {
                if (chooser.getConfig()
                        .getDefaultSelectedSignatureAndHashAlgorithm()
                        .suitableForSignatureKeyType(certKeyType)) {
                    chooser.getConfig()
                            .getCertificateChainConfig()
                            .get(0)
                            .setPublicKeyType(certKeyType);
                    return;
                }
            }
            LOGGER.warn(
                    "Could not find certificate public key type matching both cipher suite and default SignatureAndHashAlgorithm. Using first key type.");
            chooser.getConfig()
                    .getCertificateChainConfig()
                    .get(0)
                    .setPublicKeyType(certificateKeyTypes[0]);
        }
    }

    private void preparePredefinedCerts(List<CertificateEntry> entryList) {
        X509Context x509Context = new X509Context();
        for (int i = chooser.getConfig().getCertificateChainConfig().size() - 1; i >= 0; i--) {
            if (i >= entryList.size()) {
                LOGGER.warn(
                        "Not enough certificates provided for certificate chain config. Ignoring trailing config.");
                continue;
            }
            X509CertificateConfig certConfig =
                    chooser.getConfig().getCertificateChainConfig().get(i);
            prepareCert(entryList, x509Context, certConfig, i);
        }
        int certsBeyondConfigs =
                entryList.size() - chooser.getConfig().getCertificateChainConfig().size();
        if (certsBeyondConfigs > 0) {
            LOGGER.warn(
                    "Found {} more certificates than provided certificate configs. Using first config to prepare remaining entries.",
                    certsBeyondConfigs);
            X509CertificateConfig certConfig =
                    chooser.getConfig().getCertificateChainConfig().get(0);
            for (int i =
                            (entryList.size()
                                            - chooser.getConfig()
                                                    .getCertificateChainConfig()
                                                    .size())
                                    - 1;
                    i >= 0;
                    i--) {
                prepareCert(entryList, x509Context, certConfig, i);
            }
        }
        chooser.getContext().getTlsContext().setTalkingX509Context(x509Context);
    }

    private void prepareCert(
            List<CertificateEntry> entryList,
            X509Context x509Context,
            X509CertificateConfig certConfig,
            int i) {
        X509Certificate certificate = entryList.get(i).getX509certificate();
        X509Chooser chooser = new X509Chooser(certConfig, x509Context);
        X509CertificatePreparator preparator = new X509CertificatePreparator(chooser, certificate);
        preparator.prepare();
    }

    private void prepareFromEntryList(CertificateMessage msg) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (CertificateEntry pair : msg.getCertificateEntryList()) {
            CertificateEntryPreparator preparator = new CertificateEntryPreparator(chooser, pair);
            preparator.prepare();
            CertificatePairSerializer serializer =
                    new CertificatePairSerializer(pair, chooser.getSelectedProtocolVersion());
            try {
                stream.write(serializer.serialize());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] from CertificatePair", ex);
            }
        }
        msg.setCertificatesListBytes(stream.toByteArray());
        msg.setCertificatesListLength(msg.getCertificatesListBytes().getValue().length);
    }

    private void prepareRequestContext(CertificateMessage msg) {
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            msg.setRequestContext(chooser.getCertificateRequestContext());
        } else {
            msg.setRequestContext(new byte[0]);
        }
        LOGGER.debug("RequestContext: {}", msg.getRequestContext().getValue());
    }

    private void prepareRequestContextLength(CertificateMessage msg) {
        msg.setRequestContextLength(msg.getRequestContext().getValue().length);
        LOGGER.debug("RequestContextLength: {}", msg.getRequestContextLength().getValue());
    }
}
