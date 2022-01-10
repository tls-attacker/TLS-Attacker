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
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;

public class ClientHelloHandler extends HandshakeMessageHandler<ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(ClientHelloMessage message) {
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
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()
            && context.isExtensionNegotiated(ExtensionType.EARLY_DATA)) {
            try {
                adjustEarlyTrafficSecret();
                setClientRecordCipherEarly();
            } catch (CryptoException ex) {
                throw new AdjustmentException("Could not adjust", ex);
            }
        }
    }

    private boolean isCookieFieldSet(ClientHelloMessage message) {
        return message.getCookie() != null;
    }

    private void adjustClientSupportedCipherSuites(ClientHelloMessage message) {
        List<CipherSuite> suiteList = convertCipherSuites(message.getCipherSuites().getValue());
        context.setClientSupportedCipherSuites(suiteList);
        if (suiteList != null) {
            LOGGER.debug("Set ClientSupportedCipherSuites in Context to " + suiteList.toString());
        } else {
            LOGGER.debug("Set ClientSupportedCipherSuites in Context to " + null);
        }
    }

    private void adjustClientSupportedCompressions(ClientHelloMessage message) {
        List<CompressionMethod> compressionList = convertCompressionMethods(message.getCompressions().getValue());
        context.setClientSupportedCompressions(compressionList);
        LOGGER.debug("Set ClientSupportedCompressions in Context to " + compressionList.toString());
    }

    private void adjustDTLSCookie(ClientHelloMessage message) {
        byte[] dtlsCookie = message.getCookie().getValue();
        context.setDtlsCookie(dtlsCookie);
        LOGGER.debug("Set DTLS Cookie in Context to " + ArrayConverter.bytesToHexString(dtlsCookie));
    }

    private void adjustSessionID(ClientHelloMessage message) {
        byte[] sessionId = message.getSessionId().getValue();
        context.setClientSessionId(sessionId);
        LOGGER.debug("Set SessionId in Context to " + ArrayConverter.bytesToHexString(sessionId, false));
    }

    private void adjustProtocolVersion(ClientHelloMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        if (version != null) {
            context.setHighestClientProtocolVersion(version);
            LOGGER.debug("Set HighestClientProtocolVersion in Context to " + version.name());
        } else {
            LOGGER.warn("Did not Adjust ProtocolVersion since version is undefined "
                + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
        }
    }

    private void adjustRandomContext(ClientHelloMessage message) {
        context.setClientRandom(message.getRandom().getValue());
        LOGGER.debug("Set ClientRandom in Context to " + ArrayConverter.bytesToHexString(context.getClientRandom()));
    }

    private List<CompressionMethod> convertCompressionMethods(byte[] bytesToConvert) {
        List<CompressionMethod> list = new LinkedList<>();
        for (byte b : bytesToConvert) {
            CompressionMethod method = CompressionMethod.getCompressionMethod(b);
            if (method == null) {
                LOGGER.warn("Could not convert " + b + " into a CompressionMethod");
            } else {
                list.add(method);
            }
        }
        return list;
    }

    private List<CipherSuite> convertCipherSuites(byte[] bytesToConvert) {
        if (bytesToConvert.length % 2 != 0) {
            LOGGER.warn(
                "Cannot convert:" + ArrayConverter.bytesToHexString(bytesToConvert, false) + " to a List<CipherSuite>");
            return null;
        }
        List<CipherSuite> list = new LinkedList<>();

        for (int i = 0; i < bytesToConvert.length; i += 2) {
            byte[] copied = new byte[2];
            copied[0] = bytesToConvert[i];
            copied[1] = bytesToConvert[i + 1];
            CipherSuite suite = CipherSuite.getCipherSuite(copied);
            if (suite == null) {
                LOGGER.warn("Cannot convert:" + ArrayConverter.bytesToHexString(copied) + " to a CipherSuite");
            } else {
                list.add(suite);
            }
        }
        return list;
    }

    @Override
    public void adjustContextAfterSerialize(ClientHelloMessage message) {
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT
            && context.isExtensionProposed(ExtensionType.EARLY_DATA)) {
            try {
                adjustEarlyTrafficSecret();
                setClientRecordCipherEarly();
            } catch (CryptoException ex) {
                LOGGER.warn("Encountered an exception in adjust after Serialize", ex);
            }
        }
        context.setLastClientHello(message.getCompleteResultingMessage().getValue());
    }

    private void adjustEarlyTrafficSecret() throws CryptoException {
        HKDFAlgorithm hkdfAlgorithm =
            AlgorithmResolver.getHKDFAlgorithm(context.getChooser().getEarlyDataCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13,
            context.getChooser().getEarlyDataCipherSuite());

        byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], context.getChooser().getEarlyDataPsk());
        context.setEarlySecret(earlySecret);
        byte[] earlyTrafficSecret =
            HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(), context.getChooser().getEarlySecret(),
                HKDFunction.CLIENT_EARLY_TRAFFIC_SECRET, context.getDigest().getRawBytes());
        context.setClientEarlyTrafficSecret(earlyTrafficSecret);
        LOGGER.debug("EarlyTrafficSecret: " + ArrayConverter.bytesToHexString(earlyTrafficSecret));
    }

    private void setClientRecordCipherEarly() throws CryptoException {
        try {
            context.setActiveClientKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
            LOGGER.debug("Setting cipher for client to use early secrets");

            KeySet clientKeySet = KeySetGenerator.generateKeySet(context, ProtocolVersion.TLS13,
                context.getActiveClientKeySetType());

            if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
                context.getRecordLayer().updateDecryptionCipher(RecordCipherFactory.getRecordCipher(context,
                    clientKeySet, context.getChooser().getEarlyDataCipherSuite()));
            } else {
                context.getRecordLayer().updateEncryptionCipher(RecordCipherFactory.getRecordCipher(context,
                    clientKeySet, context.getChooser().getEarlyDataCipherSuite()));
            }
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error("Unable to generate KeySet - unknown algorithm");
            throw new WorkflowExecutionException(ex.toString());
        }
    }

    private void warnOnConflictingExtensions() {
        if (context.getTalkingConnectionEndType() == context.getChooser().getMyConnectionPeer()) {
            if (context.isExtensionProposed(ExtensionType.MAX_FRAGMENT_LENGTH)
                && context.isExtensionProposed(ExtensionType.RECORD_SIZE_LIMIT)) {
                // RFC 8449 says 'A server that supports the "record_size_limit" extension MUST ignore a
                // "max_fragment_length" that appears in a ClientHello if both extensions appear.', this happens
                // implicitly when determining max record data size
                LOGGER.warn("Client sent max_fragment_length AND record_size_limit extensions");
            }
        }
    }
}
