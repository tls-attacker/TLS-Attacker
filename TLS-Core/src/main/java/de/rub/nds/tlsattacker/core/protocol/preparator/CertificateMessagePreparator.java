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
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.config.delegate.CertificateDelegate;
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
        if (chooser.getSelectedProtocolVersion().is13()) {
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
                    SilentByteArrayOutputStream byteArrayOutputStream =
                            new SilentByteArrayOutputStream();
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
                if (mustCreateCertificatesDynamically()) {
                    prepareCertificateListBytesDynamically(msg, entryList);
                } else {
                    prepareExplicitCertificateListBytes(msg);
                }
                LOGGER.debug(
                        "CertificatesListBytes: {}", msg.getCertificatesListBytes().getValue());
                break;

            default:
                throw new UnsupportedOperationException("Unsupported CertificateType");
        }
    }

    private void prepareExplicitCertificateListBytes(CertificateMessage msg) {
        List<CertificateBytes> explicitChain = selectBestGivenCertificateBytes();
        List<CertificateEntry> entryList = new LinkedList<>();
        for (CertificateBytes certificateBytes : explicitChain) {
            CertificateEntry entry = new CertificateEntry(certificateBytes.getBytes());
            entryList.add(entry);
        }
        msg.setCertificateEntryList(entryList);
        prepareFromEntryList(msg);
    }

    private void prepareCertificateListBytesDynamically(
            CertificateMessage msg, List<CertificateEntry> entryList) {
        List<X509CertificateConfig> activeChainConfig =
                chooser.getConfig().getCertificateChainConfigs().get(0);
        if (entryList == null) {
            if (chooser.getConfig().getAutoAdjustCertificate()) {
                X509PublicKeyType[] certificateKeyTypes =
                        AlgorithmResolver.getSuitableLeafCertificateKeyType(
                                chooser.getSelectedCipherSuite());
                if (certificateKeyTypes.length > 0) {
                    autoSelectCertificateKeyType(certificateKeyTypes);
                } else {
                    LOGGER.warn("Could not adjust public key in certificate to fit cipher suite");
                }
            }
            // There is no certificate list in the message, this means we need to auto
            // create one
            LOGGER.debug("Building new certificate chain");
            X509CertificateChainBuilder builder = new X509CertificateChainBuilder();
            X509ChainCreationResult chainResult = builder.buildChain(activeChainConfig);
            chooser.getContext().getTlsContext().setTalkingX509Context(chainResult.getContext());
            entryList = new LinkedList<>();
            for (X509Certificate certificate :
                    chainResult.getCertificateChain().getCertificateList()) {
                entryList.add(new CertificateEntry(certificate));
            }
            msg.setCertificateEntryList(entryList);
        } else {
            preparePredefinedCerts(entryList, activeChainConfig);
        }
        prepareFromEntryList(msg);
    }

    private boolean mustCreateCertificatesDynamically() {
        return chooser.getConfig().getDefaultExplicitCertificateChain() == null
                && (chooser.getConfig().getDefaultCertificateChainBytes() == null
                        || chooser.getConfig().getDefaultCertificateChainBytes().isEmpty());
    }

    /**
     * Resolves which explicit certificate bytes chain to use. Priority 1: the single explicit chain
     * configured by the user. Priority 2: multi-cert chains — selects the chain whose leaf key type
     * matches the already-negotiated cipher suite. Returns null if no explicit chain is available.
     */
    private List<CertificateBytes> selectBestGivenCertificateBytes() {
        List<List<CertificateBytes>> certChainByteCandidates =
                chooser.getConfig().getDefaultCertificateChainBytes();
        if (chooser.getConfig().getDefaultExplicitCertificateChain() != null) {
            if (certChainByteCandidates != null && !certChainByteCandidates.isEmpty()) {
                LOGGER.warn(
                        "Both explicit certificate bytes and a pre-defined certificate byte list have been set. Will use explicit certificate bytes.");
            } else {
                LOGGER.debug("Using explicit certificate chain set in Config");
            }
            return chooser.getConfig().getDefaultExplicitCertificateChain();
        }
        LOGGER.debug("Selecting suitable certificate from pre-defined options set in Config");

        List<List<X509CertificateConfig>> certChainConfigCandidates =
                chooser.getConfig().getCertificateChainConfigs();
        X509PublicKeyType[] requiredKeyTypes =
                AlgorithmResolver.getSuitableLeafCertificateKeyType(
                        chooser.getSelectedCipherSuite());

        for (int i = 0;
                i < certChainByteCandidates.size() && i < certChainConfigCandidates.size();
                i++) {
            List<X509CertificateConfig> chainConfig = certChainConfigCandidates.get(i);
            if (chainConfig.isEmpty()) {
                continue;
            }
            X509CertificateConfig leafConfig =
                    chainConfig.get(CertificateDelegate.PREDEFINED_LEAF_CERT_INDEX);
            X509PublicKeyType leafKeyType = leafConfig.getPublicKeyType();
            for (X509PublicKeyType required : requiredKeyTypes) {
                if (required == leafKeyType) {
                    LOGGER.debug(
                            "Selected certificate chain index {} for cipher suite {}",
                            i,
                            chooser.getSelectedCipherSuite());
                    X509Context selectedContext = new X509Context(leafConfig);
                    chooser.getContext().getTlsContext().setTalkingX509Context(selectedContext);
                    return certChainByteCandidates.get(i);
                }
            }
        }
        LOGGER.warn(
                "No explicit certificate chain matches the selected cipher suite {}, using first chain given",
                chooser.getSelectedCipherSuite());
        return certChainByteCandidates.get(0);
    }

    private void autoSelectCertificateKeyType(X509PublicKeyType[] certificateKeyTypes) {
        List<X509CertificateConfig> defaultChain =
                chooser.getConfig().getCertificateChainConfigs().get(0);
        if (chooser.getConfig().getAutoAdjustSignatureAndHashAlgorithm()) {
            defaultChain.get(0).setPublicKeyType(certificateKeyTypes[0]);
        } else {
            for (X509PublicKeyType certKeyType : certificateKeyTypes) {
                if (chooser.getConfig()
                        .getDefaultSelectedSignatureAndHashAlgorithm()
                        .suitableForSignatureKeyType(certKeyType)) {
                    defaultChain.get(0).setPublicKeyType(certKeyType);
                    return;
                }
            }
            LOGGER.warn(
                    "Could not find certificate public key type matching both cipher suite and default SignatureAndHashAlgorithm. Using first key type.");
            defaultChain.get(0).setPublicKeyType(certificateKeyTypes[0]);
        }
    }

    private void preparePredefinedCerts(
            List<CertificateEntry> entryList, List<X509CertificateConfig> chainConfig) {
        X509Context x509Context = new X509Context();
        for (int i = chainConfig.size() - 1; i >= 0; i--) {
            if (i >= entryList.size()) {
                LOGGER.warn(
                        "Not enough certificates provided for certificate chain config. Ignoring trailing config.");
                continue;
            }
            X509CertificateConfig certConfig = chainConfig.get(i);
            prepareCert(entryList, x509Context, certConfig, i);
        }
        int certsBeyondConfigs = entryList.size() - chainConfig.size();
        if (certsBeyondConfigs > 0) {
            LOGGER.warn(
                    "Found {} more certificates than provided certificate configs. Using first config to prepare remaining entries.",
                    certsBeyondConfigs);
            X509CertificateConfig certConfig = chainConfig.get(0);
            for (int i = (entryList.size() - chainConfig.size()) - 1; i >= 0; i--) {
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
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        for (CertificateEntry pair : msg.getCertificateEntryList()) {
            CertificateEntryPreparator preparator = new CertificateEntryPreparator(chooser, pair);
            preparator.prepare();
            CertificatePairSerializer serializer =
                    new CertificatePairSerializer(pair, chooser.getSelectedProtocolVersion());
            stream.write(serializer.serialize());
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
