/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.protocol.exception.AdjustmentException;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyDerivator;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CoreClientHelloHandler<Message extends CoreClientHelloMessage>
        extends HandshakeMessageHandler<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CoreClientHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(Message message) {
        adjustProtocolVersion(message);
        adjustSessionID(message);
        adjustClientSupportedCipherSuites(message);
        adjustClientSupportedCompressions(message);
        if (isCookieFieldSet(message)) {
            adjustDTLSCookie(message);
        }
        adjustExtensions(message);
        warnOnConflictingExtensions();
        adjustRandomContext(message);
        if ((tlsContext.getChooser().getSelectedProtocolVersion().is13())
                && tlsContext.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
            try {
                adjustEarlyTrafficSecret();
                setClientRecordCipherEarly();
            } catch (CryptoException ex) {
                throw new AdjustmentException("Could not adjust", ex);
            }
        }
    }

    private boolean isCookieFieldSet(Message message) {
        return message.getCookie() != null;
    }

    private void adjustClientSupportedCipherSuites(Message message) {
        List<CipherSuite> suiteList = convertCipherSuites(message.getCipherSuites().getValue());
        tlsContext.setClientSupportedCipherSuites(suiteList);
        if (suiteList != null) {
            LOGGER.debug("Set ClientSupportedCipherSuites in Context to {}", suiteList.toString());
        } else {
            LOGGER.debug("Set ClientSupportedCipherSuites in Context to null");
        }
    }

    private void adjustClientSupportedCompressions(Message message) {
        List<CompressionMethod> compressionList =
                convertCompressionMethods(message.getCompressions().getValue());
        tlsContext.setClientSupportedCompressions(compressionList);
        LOGGER.debug(
                "Set ClientSupportedCompressions in Context to {}", compressionList.toString());
    }

    private void adjustDTLSCookie(Message message) {
        byte[] dtlsCookie = message.getCookie().getValue();
        tlsContext.setDtlsCookie(dtlsCookie);
        LOGGER.debug("Set DTLS Cookie in Context to {}", dtlsCookie);
    }

    private void adjustSessionID(Message message) {
        byte[] sessionId = message.getSessionId().getValue();
        tlsContext.setClientSessionId(sessionId);
        LOGGER.debug("Set SessionId in Context to {}", sessionId);
    }

    private void adjustProtocolVersion(Message message) {
        ProtocolVersion version =
                ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        if (version != null) {
            tlsContext.setHighestClientProtocolVersion(version);
            LOGGER.debug("Set HighestClientProtocolVersion in Context to {}", version.name());
        } else {
            LOGGER.warn(
                    "Did not Adjust ProtocolVersion since version is undefined {}",
                    message.getProtocolVersion().getValue());
        }
    }

    private void adjustRandomContext(Message message) {
        tlsContext.setClientRandom(message.getRandom().getValue());
        LOGGER.debug("Set ClientRandom in Context to {}", tlsContext.getClientRandom());
    }

    private List<CompressionMethod> convertCompressionMethods(byte[] bytesToConvert) {
        List<CompressionMethod> list = new LinkedList<>();
        for (byte b : bytesToConvert) {
            CompressionMethod method = CompressionMethod.getCompressionMethod(b);
            if (method == null) {
                LOGGER.warn("Could not convert {} into a CompressionMethod", b);
            } else {
                list.add(method);
            }
        }
        return list;
    }

    private List<CipherSuite> convertCipherSuites(byte[] bytesToConvert) {
        if (bytesToConvert.length % 2 != 0) {
            LOGGER.warn("Cannot convert: {} to a List<CipherSuite>", bytesToConvert);
            return null;
        }
        List<CipherSuite> list = new LinkedList<>();

        for (int i = 0; i < bytesToConvert.length; i += 2) {
            byte[] copied = new byte[2];
            copied[0] = bytesToConvert[i];
            copied[1] = bytesToConvert[i + 1];
            CipherSuite suite = CipherSuite.getCipherSuite(copied);
            if (suite == null) {
                LOGGER.warn("Cannot convert {} to a CipherSuite", copied);
            } else {
                list.add(suite);
            }
        }
        return list;
    }

    @Override
    public void adjustContextAfterSerialize(Message message) {
        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
                && tlsContext.isExtensionProposed(ExtensionType.EARLY_DATA)) {
            try {
                adjustEarlyTrafficSecret();
                setClientRecordCipherEarly();
            } catch (CryptoException ex) {
                LOGGER.warn("Encountered an exception in adjust after Serialize", ex);
            }
        }
    }

    private void adjustEarlyTrafficSecret() throws CryptoException {
        HKDFAlgorithm hkdfAlgorithm =
                AlgorithmResolver.getHKDFAlgorithm(
                        tlsContext.getChooser().getEarlyDataCipherSuite());
        DigestAlgorithm digestAlgo =
                AlgorithmResolver.getDigestAlgorithm(
                        ProtocolVersion.TLS13, tlsContext.getChooser().getEarlyDataCipherSuite());

        byte[] earlySecret =
                HKDFunction.extract(
                        hkdfAlgorithm, new byte[0], tlsContext.getChooser().getEarlyDataPsk());
        tlsContext.setEarlySecret(earlySecret);
        byte[] earlyTrafficSecret =
                HKDFunction.deriveSecret(
                        hkdfAlgorithm,
                        digestAlgo.getJavaName(),
                        tlsContext.getChooser().getEarlySecret(),
                        HKDFunction.CLIENT_EARLY_TRAFFIC_SECRET,
                        tlsContext.getDigest().getRawBytes(),
                        tlsContext.getChooser().getSelectedProtocolVersion());
        tlsContext.setClientEarlyTrafficSecret(earlyTrafficSecret);
        LOGGER.debug("EarlyTrafficSecret: {}", earlyTrafficSecret);
    }

    private void setClientRecordCipherEarly() throws CryptoException {
        try {
            tlsContext.setActiveClientKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
            LOGGER.debug("Setting cipher for client to use early secrets");

            KeySet clientKeySet =
                    KeyDerivator.generateKeySet(
                            tlsContext,
                            ProtocolVersion.TLS13,
                            tlsContext.getActiveClientKeySetType());

            if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
                tlsContext
                        .getRecordLayer()
                        .updateDecryptionCipher(
                                RecordCipherFactory.getRecordCipher(
                                        tlsContext,
                                        clientKeySet,
                                        tlsContext.getChooser().getEarlyDataCipherSuite(),
                                        tlsContext.getReadConnectionId()));
            } else {
                if (tlsContext.getRecordLayer() != null) {
                    tlsContext
                            .getRecordLayer()
                            .updateEncryptionCipher(
                                    RecordCipherFactory.getRecordCipher(
                                            tlsContext,
                                            clientKeySet,
                                            tlsContext.getChooser().getEarlyDataCipherSuite(),
                                            tlsContext.getWriteConnectionId()));
                }
            }
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error("Unable to generate KeySet - unknown algorithm");
            throw new CryptoException(ex);
        }
    }

    private void warnOnConflictingExtensions() {
        if (tlsContext.getTalkingConnectionEndType()
                == tlsContext.getChooser().getMyConnectionPeer()) {
            if (tlsContext.isExtensionProposed(ExtensionType.MAX_FRAGMENT_LENGTH)
                    && tlsContext.isExtensionProposed(ExtensionType.RECORD_SIZE_LIMIT)) {
                // RFC 8449 says 'A server that supports the "record_size_limit" extension MUST
                // ignore a
                // "max_fragment_length" that appears in a ClientHello if both extensions appear.',
                // this happens
                // implicitly when determining max record data size
                LOGGER.warn("Client sent max_fragment_length AND record_size_limit extensions");
            }
        }
    }
}
