/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.hpke.HpkeUtil;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.DragonFlyKeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.keyshare.DragonFlyKeyShareEntryParser;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.session.Session;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloHandler extends HandshakeMessageHandler<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String echLabel = "ech accept confirmation";

    private static final String echHrrLabel = "hrr accept confirmation";

    public ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(ServerHelloMessage message) {
        if (tlsContext.getConfig().isAddEncryptedClientHelloExtension()
                && tlsContext.getTransportHandler().getConnectionEndType()
                        == ConnectionEndType.CLIENT) {
            determineEncryptedClientHelloSupport(message, message.isTls13HelloRetryRequest());
        } else if (!tlsContext.getConfig().isAddEncryptedClientHelloExtension()) {
            LOGGER.debug("Not determining Server ECH support because ECH disabled");
        } else if (tlsContext.getTransportHandler().getConnectionEndType()
                != ConnectionEndType.CLIENT) {
            LOGGER.debug("Not determining Server ECH support because we are Server");
        }
        adjustSelectedProtocolVersion(message);
        adjustSelectedCompression(message);
        adjustSelectedSessionID(message);
        adjustSelectedCipherSuite(message);
        adjustServerRandom(message);
        adjustExtensions(message);
        warnOnConflictingExtensions();
        if (!message.isTls13HelloRetryRequest()) {
            if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
                KeyShareStoreEntry keyShareStoreEntry = adjustKeyShareStoreEntry();
                adjustHandshakeTrafficSecrets(keyShareStoreEntry);
                if (tlsContext.getTalkingConnectionEndType()
                        != tlsContext.getChooser().getConnectionEndType()) {
                    setServerRecordCipher();
                }
            }
            adjustPRF(message);
            if (tlsContext.hasSession(tlsContext.getChooser().getServerSessionId())) {
                LOGGER.info("Resuming Session");
                LOGGER.debug("Loading MasterSecret");
                Session session =
                        tlsContext.getIdSession(tlsContext.getChooser().getServerSessionId());
                tlsContext.setMasterSecret(session.getMasterSecret());
            }
        } else {
            adjustHelloRetryDigest(message);
        }
    }

    private void adjustSelectedCipherSuite(ServerHelloMessage message) {
        CipherSuite suite = null;
        if (message.getSelectedCipherSuite() != null) {
            suite = CipherSuite.getCipherSuite(message.getSelectedCipherSuite().getValue());
        }

        if (suite != null) {
            tlsContext.setSelectedCipherSuite(suite);
            LOGGER.debug("Set SelectedCipherSuite in Context to " + suite.name());
        } else {
            LOGGER.warn("Unknown CipherSuite, did not adjust Context");
        }
    }

    private void adjustServerRandom(ServerHelloMessage message) {
        tlsContext.setServerRandom(message.getRandom().getValue());
        LOGGER.debug("Set ServerRandom in Context to {}", tlsContext.getServerRandom());
    }

    private void adjustSelectedCompression(ServerHelloMessage message) {

        CompressionMethod method = null;
        if (message.getSelectedCompressionMethod() != null) {
            method =
                    CompressionMethod.getCompressionMethod(
                            message.getSelectedCompressionMethod().getValue());
        }

        if (method != null) {
            tlsContext.setSelectedCompressionMethod(method);
            LOGGER.debug("Set SelectedCompressionMethod in Context to " + method.name());
        } else {
            LOGGER.warn("Not adjusting CompressionMethod - Method is null!");
        }
    }

    private void adjustSelectedSessionID(ServerHelloMessage message) {
        byte[] sessionID = message.getSessionId().getValue();
        tlsContext.setServerSessionId(sessionID);
        LOGGER.debug("Set SessionID in Context to {}", sessionID);
    }

    private void adjustSelectedProtocolVersion(ServerHelloMessage message) {
        ProtocolVersion version = null;

        if (message.getProtocolVersion() != null) {
            version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        }

        if (version != null) {
            tlsContext.setSelectedProtocolVersion(version);
            LOGGER.debug("Set SelectedProtocolVersion in Context to " + version.name());
        } else {
            LOGGER.warn(
                    "Did not Adjust ProtocolVersion since version is undefined {}",
                    message.getProtocolVersion().getValue());
        }
    }

    private void adjustPRF(ServerHelloMessage message) {
        Chooser chooser = tlsContext.getChooser();
        if (!chooser.getSelectedProtocolVersion().isSSL()) {
            tlsContext.setPrfAlgorithm(
                    AlgorithmResolver.getPRFAlgorithm(
                            chooser.getSelectedProtocolVersion(),
                            chooser.getSelectedCipherSuite()));
        }
    }

    private void setServerRecordCipher() {
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        LOGGER.debug("Setting cipher for server to use handshake secrets");
        KeySet serverKeySet = getTls13KeySet(tlsContext, tlsContext.getActiveServerKeySetType());

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext
                    .getRecordLayer()
                    .updateDecryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet, false));
        } else {
            tlsContext
                    .getRecordLayer()
                    .updateEncryptionCipher(
                            RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet, true));
        }
    }

    private KeySet getTls13KeySet(TlsContext tlsContext, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            return KeySetGenerator.generateKeySet(
                    tlsContext,
                    this.tlsContext.getChooser().getSelectedProtocolVersion(),
                    keySetType);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    @Override
    public void adjustContextAfterSerialize(ServerHelloMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()
                && !message.isTls13HelloRetryRequest()) {
            setServerRecordCipher();
        }
    }

    private void adjustHandshakeTrafficSecrets(KeyShareStoreEntry keyShareStoreEntry) {
        HKDFAlgorithm hkdfAlgorithm =
                AlgorithmResolver.getHKDFAlgorithm(
                        tlsContext.getChooser().getSelectedCipherSuite());
        DigestAlgorithm digestAlgo =
                AlgorithmResolver.getDigestAlgorithm(
                        tlsContext.getChooser().getSelectedProtocolVersion(),
                        tlsContext.getChooser().getSelectedCipherSuite());

        try {
            int macLength =
                    Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] psk =
                    (tlsContext.getConfig().isUsePsk() || tlsContext.getPsk() != null)
                            ? tlsContext.getChooser().getPsk()
                            : new byte[macLength]; // use PSK if available
            byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], psk);
            byte[] saltHandshakeSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            earlySecret,
                            HKDFunction.DERIVED,
                            new byte[0]);
            byte[] sharedSecret;
            BigInteger privateKey = tlsContext.getConfig().getKeySharePrivate();
            if (tlsContext.getChooser().getSelectedCipherSuite().isPWD()) {
                sharedSecret = computeSharedPWDSecret(keyShareStoreEntry);
            } else {
                sharedSecret =
                        KeyShareCalculator.computeSharedSecret(
                                keyShareStoreEntry.getGroup(),
                                privateKey,
                                keyShareStoreEntry.getPublicKey());
                // This is a workaround for Tls1.3 InvalidCurve attacks
                if (tlsContext.getConfig().getDefaultPreMasterSecret().length > 0) {
                    LOGGER.debug("Using specified PMS instead of computed PMS");
                    sharedSecret = tlsContext.getConfig().getDefaultPreMasterSecret();
                }
            }
            byte[] handshakeSecret =
                    HKDFunction.extract(hkdfAlgorithm, saltHandshakeSecret, sharedSecret);
            tlsContext.setHandshakeSecret(handshakeSecret);
            LOGGER.debug("Set handshakeSecret in Context to {}", handshakeSecret);
            byte[] clientHandshakeTrafficSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            handshakeSecret,
                            HKDFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                            tlsContext.getDigest().getRawBytes());
            tlsContext.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
            LOGGER.debug(
                    "Set clientHandshakeTrafficSecret in Context to {}",
                    clientHandshakeTrafficSecret);
            byte[] serverHandshakeTrafficSecret =
                    HKDFunction.deriveSecret(
                            hkdfAlgorithm,
                            digestAlgo.getJavaName(),
                            handshakeSecret,
                            HKDFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET,
                            tlsContext.getDigest().getRawBytes());
            tlsContext.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
            LOGGER.debug(
                    "Set serverHandshakeTrafficSecret in Context to {}",
                    serverHandshakeTrafficSecret);
        } catch (CryptoException | NoSuchAlgorithmException ex) {
            throw new AdjustmentException(ex);
        }
    }

    private byte[] computeSharedPWDSecret(KeyShareStoreEntry keyShare) throws CryptoException {
        Chooser chooser = tlsContext.getChooser();
        EllipticCurve curve = CurveFactory.getCurve(keyShare.getGroup());
        DragonFlyKeyShareEntryParser parser =
                new DragonFlyKeyShareEntryParser(
                        new ByteArrayInputStream(keyShare.getPublicKey()), keyShare.getGroup());
        DragonFlyKeyShareEntry dragonFlyKeyShareEntry = new DragonFlyKeyShareEntry();
        parser.parse(dragonFlyKeyShareEntry);
        int curveSize = curve.getModulus().bitLength();
        Point keySharePoint =
                PointFormatter.fromRawFormat(
                        keyShare.getGroup(), dragonFlyKeyShareEntry.getRawPublicKey());

        BigInteger scalar = dragonFlyKeyShareEntry.getScalar();
        Point passwordElement =
                PWDComputations.computePasswordElement(tlsContext.getChooser(), curve);
        BigInteger privateKeyScalar;
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            privateKeyScalar =
                    new BigInteger(1, chooser.getConfig().getDefaultClientPWDPrivate())
                            .mod(curve.getBasePointOrder());
        } else {
            privateKeyScalar =
                    new BigInteger(1, chooser.getConfig().getDefaultServerPWDPrivate())
                            .mod(curve.getBasePointOrder());
        }
        LOGGER.debug("Element: {}", () -> PointFormatter.toRawFormat(keySharePoint));
        LOGGER.debug("Scalar: {}", () -> ArrayConverter.bigIntegerToByteArray(scalar));

        Point sharedSecret =
                curve.mult(
                        privateKeyScalar,
                        curve.add(curve.mult(scalar, passwordElement), keySharePoint));
        return ArrayConverter.bigIntegerToByteArray(
                sharedSecret.getFieldX().getData(), curveSize / Bits.IN_A_BYTE, true);
    }

    /**
     * compare draft-ietf-tls-esni-14 After the client sends its encryptedClientHelloMessage the
     * server can choose whether to accept or reject it. It then proceeds the handshake with either
     * the unencrypted OuterClientHello (rejection) or the encrypted InnerClientHello (acceptance).
     * However, the server has to tell the client whether it accepted or rejected its
     * EncryptedClientHello so that the client might also continue with the correct clienthello. To
     * not leak EncryptedClientHello acceptance or rejection to eavesdroppers, the server "hides"
     * its acceptance in its ServerRandom. When the server rejects the client's
     * EncryptedClientHello, it selects the ServerRandom as usual. When the server accepts the
     * client's EncryptedClientHello it sets the last 8 byte of the ServerRandom to the so-called
     * "accept- confirmation". The accept-confirmation is a the result of the selected HKDF with the
     * ClientRandom the static string "ech accept confirmation" and the transcript of the selected
     * ECH config as input. The client has to check whether the last 8 bytes of the ServerRandom
     * equal the HKDF's output to determine the server's acceptance or rejection of the client's
     * EncryptedClientHello
     *
     * @param message
     * @param isHelloRetryRequestMessage
     */
    private void determineEncryptedClientHelloSupport(
            ServerHelloMessage message, boolean isHelloRetryRequestMessage) {
        String label;
        // in ServerHello.random for ServerHello and in encryptedClientHelloExtension for HRR
        byte[] acceptConfirmationServer;

        byte[] originalServerHello = message.getCompleteResultingMessage().getValue();
        byte[] serverHello = originalServerHello.clone();

        if (!isHelloRetryRequestMessage) {
            label = echLabel;
            acceptConfirmationServer =
                    acceptConfirmationServer(message, originalServerHello, serverHello);

        } else {
            label = echHrrLabel;
            acceptConfirmationServer = acceptConfirmationServerHrr(message, serverHello);
        }
        // also acquire the transcript of the last sent ClientHello
        if (acceptConfirmationServer == null) {
            return;
        }

        byte[] transcriptEchConf = computeEchDigest(serverHello);
        computeAcceptConfirmation(label, transcriptEchConf, acceptConfirmationServer, message);
    }

    private byte[] acceptConfirmationServer(
            ServerHelloMessage message, byte[] originalServerHello, byte[] serverHello) {
        // The server accepted ECH if the last 8 bytes of the server random are deterministic
        if (message.getRandom().getValue().length < 8) {
            LOGGER.warn("Server returned short ClientHello");
            return null;
        }
        // replace the last 8 bytes of the random with zero bytes
        byte[] serverRandom = message.getRandom().getValue();
        byte[] serverRandomTruncatedPart =
                Arrays.copyOfRange(serverRandom, serverRandom.length - 8, serverRandom.length);

        // replace the last 8 bytes of the server random with 0 in the transcript
        int startIndex = HpkeUtil.indexOf(originalServerHello, serverRandomTruncatedPart);
        System.arraycopy(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}, 0, serverHello, startIndex, 8);
        return serverRandomTruncatedPart;
    }

    private byte[] acceptConfirmationServerHrr(ServerHelloMessage message, byte[] serverHello) {
        // TODO: this does not work with the only reference server (openssl) we have
        // in an ECH HRR the server accepted ECH if the 8 bytes of the encryptedClientHelloExtension
        // are
        // deterministic
        // TODO: trace with RFC updates because this seems completely bonkers. For some reason the
        // extension is
        // filled with 8 bytes contrary to its specification in the beginning of the document
        // replace the 8 bytes of the encryptedClientHelloExtension with zeroes

        // holds 8 byte comparison string
        EncryptedClientHelloExtensionMessage extensionMessage =
                message.getExtension(EncryptedClientHelloExtensionMessage.class);
        if (extensionMessage == null) {
            LOGGER.debug(
                    "The server did not include an encryptedClientHello message in its HelloRetryRequest");
            return null;
        }

        byte[] extensionContent = extensionMessage.getAcceptConfirmation().getValue();

        // replace the last 8 bytes of payload with 0 in the transcript

        int startIndex = HpkeUtil.indexOf(serverHello, extensionContent);
        System.arraycopy(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}, 0, serverHello, startIndex, 8);
        return extensionContent;
    }

    private byte[] computeEchDigest(byte[] serverHello) {
        byte[] lastClientHello = tlsContext.getChooser().getLastClientHello();
        // digest clientHello and serverHello
        MessageDigestCollector echDigest = new MessageDigestCollector();

        LOGGER.debug("ClientHelloInner: " + ArrayConverter.bytesToHexString(lastClientHello));
        LOGGER.debug("ServerHello: " + ArrayConverter.bytesToHexString(serverHello));
        echDigest.append(lastClientHello);
        echDigest.append(serverHello);
        LOGGER.debug(
                "Complete resulting digest: "
                        + ArrayConverter.bytesToHexString(echDigest.getRawBytes()));

        Chooser chooser = tlsContext.getChooser();
        byte[] transcriptEchConf =
                echDigest.digest(
                        chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite());
        LOGGER.debug(
                "Transcript Ech Config: " + ArrayConverter.bytesToHexString(transcriptEchConf));
        return transcriptEchConf;
    }

    private void computeAcceptConfirmation(
            String label,
            byte[] transcriptEchConf,
            byte[] acceptConfirmationServer,
            ServerHelloMessage message) {
        Chooser chooser = tlsContext.getChooser();
        HKDFAlgorithm hkdfAlgorithm =
                chooser.getEchConfig().getHpkeKeyDerivationFunction().getHkdfAlgorithm();
        try {
            ClientHelloMessage innerClientHello = chooser.getInnerClientHello();
            byte[] extract =
                    HKDFunction.extract(
                            hkdfAlgorithm, null, innerClientHello.getRandom().getValue());
            LOGGER.debug("Extract: " + ArrayConverter.bytesToHexString(extract));
            byte[] acceptConfirmationClient =
                    HKDFunction.expandLabel(hkdfAlgorithm, extract, label, transcriptEchConf, 8);
            LOGGER.debug(
                    "Accept Confirmation Calculated: "
                            + ArrayConverter.bytesToHexString(acceptConfirmationClient));
            LOGGER.debug(
                    "Accept Confirmation Received: "
                            + ArrayConverter.bytesToHexString(acceptConfirmationServer));
            if (Arrays.equals(acceptConfirmationClient, acceptConfirmationServer)) {
                // mark ECH support in context
                tlsContext.setSupportsECH(true);
                // update tlscontext and digest to clientHelloInner
                ClientHelloHandler clientHelloHandler = new ClientHelloHandler(tlsContext);
                clientHelloHandler.adjustContext(innerClientHello);
                chooser.getContext().getTlsContext().getDigest().reset();
                updateDigest(innerClientHello, false);
                updateDigest(message, false);
                LOGGER.info("Server supports ECH");
            }
        } catch (CryptoException e) {
            LOGGER.warn("Could not compute accept confirmation of Server Hello: ", e);
        }
    }

    private void adjustHelloRetryDigest(ServerHelloMessage message) {
        try {
            byte[] lastClientHello = tlsContext.getChooser().getLastClientHello();
            LOGGER.debug(
                    "Replacing current digest for Hello Retry Request using Client Hello: {}",
                    lastClientHello);

            DigestAlgorithm algorithm =
                    AlgorithmResolver.getDigestAlgorithm(
                            ProtocolVersion.TLS13,
                            tlsContext.getChooser().getSelectedCipherSuite());
            MessageDigest hash = MessageDigest.getInstance(algorithm.getJavaName());
            hash.update(lastClientHello);
            byte[] clientHelloHash = hash.digest();
            byte[] serverHelloBytes = message.getCompleteResultingMessage().getValue();

            tlsContext.getDigest().setRawBytes(HandshakeMessageType.MESSAGE_HASH.getArrayValue());
            tlsContext
                    .getDigest()
                    .append(
                            ArrayConverter.intToBytes(
                                    clientHelloHash.length,
                                    HandshakeByteLength.MESSAGE_LENGTH_FIELD));
            tlsContext.getDigest().append(clientHelloHash);
            tlsContext.getDigest().append(serverHelloBytes);
            LOGGER.debug("Complete resulting digest: {}", tlsContext.getDigest().getRawBytes());
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error(ex);
        }
    }

    private void warnOnConflictingExtensions() {
        if (tlsContext.getTalkingConnectionEndType()
                == tlsContext.getChooser().getMyConnectionPeer()) {
            // for TLS 1.3, this is handled in encrypted extensions
            if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
                if (tlsContext.isExtensionNegotiated(ExtensionType.MAX_FRAGMENT_LENGTH)
                        && tlsContext.isExtensionNegotiated(ExtensionType.RECORD_SIZE_LIMIT)) {
                    // this is supposed to result in a fatal error, just warning for now
                    LOGGER.warn("Server sent max_fragment_length AND record_size_limit extensions");
                }
            }
        }
    }

    private KeyShareStoreEntry adjustKeyShareStoreEntry() {
        KeyShareStoreEntry selectedKeyShareStore;
        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            selectedKeyShareStore = tlsContext.getChooser().getServerKeyShare();
        } else {
            Integer pos = null;
            for (KeyShareStoreEntry entry : tlsContext.getChooser().getClientKeyShares()) {
                if (Arrays.equals(
                        entry.getGroup().getValue(),
                        tlsContext.getChooser().getServerKeyShare().getGroup().getValue())) {
                    pos = tlsContext.getChooser().getClientKeyShares().indexOf(entry);
                }
            }
            if (pos == null) {
                LOGGER.warn(
                        "Client did not send the KeyShareType we expected. Choosing first in his List");
                pos = 0;
            }

            selectedKeyShareStore = tlsContext.getChooser().getClientKeyShares().get(pos);
        }
        tlsContext.setSelectedGroup(selectedKeyShareStore.getGroup());

        if (selectedKeyShareStore.getGroup().isCurve()) {
            Point publicPoint;
            if (tlsContext.getChooser().getSelectedCipherSuite().isPWD()) {
                publicPoint =
                        PointFormatter.fromRawFormat(
                                selectedKeyShareStore.getGroup(),
                                selectedKeyShareStore.getPublicKey());
            } else {
                publicPoint =
                        PointFormatter.formatFromByteArray(
                                selectedKeyShareStore.getGroup(),
                                selectedKeyShareStore.getPublicKey());
            }
            tlsContext.setServerEcPublicKey(publicPoint);
        } else {
            tlsContext.setServerDhPublicKey(new BigInteger(selectedKeyShareStore.getPublicKey()));
        }

        return selectedKeyShareStore;
    }
}
