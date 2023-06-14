/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeUtil;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloPreparator extends HelloMessagePreparator<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String label = "ech accept confirmation";

    private final ServerHelloMessage msg;

    public ServerHelloPreparator(Chooser chooser, ServerHelloMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing ServerHelloMessage");
        prepareProtocolVersion();
        prepareRandom();
        prepareSessionID();
        prepareSessionIDLength();

        prepareCipherSuite();
        prepareCompressionMethod();
        if (chooser.getConfig().isRespectClientProposedExtensions()
                && msg.getExtensions() == null) {
            selectExtensions();
        }
        if (!chooser.getConfig().getHighestProtocolVersion().isSSL()
                || (chooser.getConfig().getHighestProtocolVersion().isSSL()
                        && chooser.getConfig().isAddExtensionsInSSL())) {
            prepareExtensions();
            prepareExtensionLength();
        }
        if (chooser.getContext().getTlsContext().isSupportsECH()) {
            prepareEchRandom();
        }
    }

    private void selectExtensions() {
        List<ExtensionType> permittedUnproposedExtensionTypes = new LinkedList<>();
        Set<ExtensionType> forbiddenExtensionTypes = new HashSet<>();
        if (chooser.getClientSupportedCipherSuites()
                .contains(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
            permittedUnproposedExtensionTypes.add(ExtensionType.RENEGOTIATION_INFO);
        }

        CipherSuite selectedCipherSuite =
                CipherSuite.getCipherSuite(msg.getSelectedCipherSuite().getValue());
        if (selectedCipherSuite != null
                && AlgorithmResolver.getKeyExchangeAlgorithm(selectedCipherSuite) != null
                && !AlgorithmResolver.getKeyExchangeAlgorithm(selectedCipherSuite).isEC()) {
            forbiddenExtensionTypes.add(ExtensionType.EC_POINT_FORMATS);
        }

        if (selectedCipherSuite != null && selectedCipherSuite.isTLS13()) {
            forbiddenExtensionTypes.addAll(ExtensionType.getNonTls13Extensions());
        } else {
            forbiddenExtensionTypes.addAll(ExtensionType.getTls13OnlyExtensions());
        }

        permittedUnproposedExtensionTypes.add(ExtensionType.COOKIE);
        autoSelectExtensions(
                chooser.getConfig(),
                chooser.getContext().getTlsContext().getProposedExtensions(),
                forbiddenExtensionTypes,
                permittedUnproposedExtensionTypes.toArray(ExtensionType[]::new));
    }

    private void prepareCipherSuite() {
        if (chooser.getConfig().isEnforceSettings()) {
            msg.setSelectedCipherSuite(
                    chooser.getConfig().getDefaultSelectedCipherSuite().getByteValue());
        } else {
            CipherSuite selectedSuite = null;
            for (CipherSuite suite : chooser.getConfig().getDefaultServerSupportedCipherSuites()) {
                if (chooser.getClientSupportedCipherSuites().contains(suite)) {
                    selectedSuite = suite;
                    break;
                }
            }
            if (selectedSuite == null) {
                selectedSuite = chooser.getConfig().getDefaultSelectedCipherSuite();
                LOGGER.warn(
                        "No CipherSuites in common, falling back to defaultSelectedCipherSuite");
            }
            msg.setSelectedCipherSuite(selectedSuite.getByteValue());
        }
        LOGGER.debug(
                "SelectedCipherSuite: "
                        + ArrayConverter.bytesToHexString(msg.getSelectedCipherSuite().getValue()));
    }

    private void prepareCompressionMethod() {
        if (chooser.getConfig().isEnforceSettings()) {
            msg.setSelectedCompressionMethod(
                    chooser.getConfig().getDefaultSelectedCompressionMethod().getValue());
        } else {
            CompressionMethod selectedCompressionMethod = null;
            for (CompressionMethod method :
                    chooser.getConfig().getDefaultServerSupportedCompressionMethods()) {
                if (chooser.getClientSupportedCompressions().contains(method)) {
                    selectedCompressionMethod = method;
                    break;
                }
            }
            if (selectedCompressionMethod == null) {
                selectedCompressionMethod =
                        chooser.getConfig().getDefaultSelectedCompressionMethod();
                LOGGER.warn(
                        "No CompressionMethod in common, falling back to defaultSelectedCompressionMethod");
            }
            msg.setSelectedCompressionMethod(selectedCompressionMethod.getValue());
        }
        LOGGER.debug("SelectedCompressionMethod: " + msg.getSelectedCompressionMethod().getValue());
    }

    private void prepareSessionID() {
        if (chooser.getConfig().getHighestProtocolVersion().isTLS13()) {
            msg.setSessionId(chooser.getClientSessionId());
        } else {
            msg.setSessionId(chooser.getServerSessionId());
        }
        LOGGER.debug(
                "SessionID: " + ArrayConverter.bytesToHexString(msg.getSessionId().getValue()));
    }

    private void prepareProtocolVersion() {
        ProtocolVersion ourVersion = chooser.getConfig().getHighestProtocolVersion();
        if (chooser.getConfig().getHighestProtocolVersion().isTLS13()) {
            ourVersion = ProtocolVersion.TLS12;
        }

        ProtocolVersion clientVersion = chooser.getHighestClientProtocolVersion();
        int intRepresentationOurVersion =
                ourVersion.getValue()[0] * 0x100 + ourVersion.getValue()[1];
        int intRepresentationClientVersion =
                clientVersion.getValue()[0] * 0x100 + clientVersion.getValue()[1];
        if (chooser.getConfig().isEnforceSettings()) {
            msg.setProtocolVersion(ourVersion.getValue());
        } else {
            if (chooser.getHighestClientProtocolVersion().isDTLS()
                    && chooser.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want dtls
                if (intRepresentationClientVersion <= intRepresentationOurVersion) {
                    msg.setProtocolVersion(ourVersion.getValue());
                } else {
                    msg.setProtocolVersion(clientVersion.getValue());
                }
            }
            if (!chooser.getHighestClientProtocolVersion().isDTLS()
                    && !chooser.getConfig().getHighestProtocolVersion().isDTLS()) {
                // We both want tls
                if (intRepresentationClientVersion >= intRepresentationOurVersion) {
                    msg.setProtocolVersion(ourVersion.getValue());
                } else {
                    msg.setProtocolVersion(clientVersion.getValue());
                }
            } else {
                msg.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());
            }
        }
        LOGGER.debug(
                "ProtocolVersion: "
                        + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

    protected void prepareEchRandom() {
        // ECH mandates to replace the last 8 bytes of the client random with deterministic values
        // Section 7.2 esni_draft_14

        TlsContext tlsContext = chooser.getContext().getTlsContext();
        ClientHelloMessage innerClientHello = chooser.getInnerClientHello();
        byte[] clientRandom = innerClientHello.getRandom().getValue();
        byte[] serverRandom = chooser.getServerRandom();
        byte[] serverRandomTruncatedPart =
                Arrays.copyOfRange(serverRandom, serverRandom.length - 8, serverRandom.length);
        byte[] clientHelloInner = chooser.getLastClientHello();
        byte[] acceptConfirmation = new byte[] {0, 0, 0, 0, 0, 0, 0, 0};

        // serialize server hello and replace last 8 bytes of server random with null bytes
        byte[] serverHello = msg.getSerializer(tlsContext).serializeHandshakeMessageContent();
        byte[] type = new byte[] {HandshakeMessageType.SERVER_HELLO.getValue()};
        byte[] length = ArrayConverter.intToBytes(serverHello.length, 3);
        serverHello = ArrayConverter.concatenate(type, length, serverHello);

        // replace random

        int startIndex = HpkeUtil.indexOf(serverHello, serverRandomTruncatedPart);
        System.arraycopy(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}, 0, serverHello, startIndex, 8);

        // digest clientHello and serverHello
        MessageDigestCollector echDigest = new MessageDigestCollector();
        LOGGER.debug("ClientHelloInner: " + ArrayConverter.bytesToHexString(clientHelloInner));
        LOGGER.debug("ServerHello: " + ArrayConverter.bytesToHexString(serverHello));
        echDigest.append(clientHelloInner);
        echDigest.append(serverHello);
        LOGGER.debug(
                "Complete resulting digest: "
                        + ArrayConverter.bytesToHexString(echDigest.getRawBytes()));

        byte[] transcriptEchConf =
                echDigest.digest(
                        chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite());
        LOGGER.debug(
                "Transcript Ech Config: " + ArrayConverter.bytesToHexString(transcriptEchConf));

        // compute accept_confirmation
        HKDFAlgorithm hkdfAlgorithm =
                chooser.getEchConfig().getHpkeKeyDerivationFunction().getHkdfAlgorithm();
        try {
            byte[] extract = HKDFunction.extract(hkdfAlgorithm, null, clientRandom);
            LOGGER.debug("Extract: " + ArrayConverter.bytesToHexString(extract));
            acceptConfirmation =
                    HKDFunction.expandLabel(hkdfAlgorithm, extract, label, transcriptEchConf, 8);
            LOGGER.debug(
                    "Accept Confirmation: " + ArrayConverter.bytesToHexString(acceptConfirmation));
        } catch (CryptoException e) {
            LOGGER.warn("Could not calculate accept confirmation");
        }
        // set serverRandom accordingly
        byte[] newRandom =
                ArrayConverter.concatenate(
                        Arrays.copyOfRange(serverRandom, 0, serverRandom.length - 8),
                        acceptConfirmation);
        msg.setRandom(newRandom);
    }
}
