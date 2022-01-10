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
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.DragonFlyKeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.keyshare.DragonFlyKeyShareEntryParser;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.state.session.Session;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Mac;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class ServerHelloHandler extends HandshakeMessageHandler<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(ServerHelloMessage message) {
        adjustSelectedProtocolVersion(message);
        adjustSelectedCompression(message);
        adjustSelectedSessionID(message);
        adjustSelectedCipherSuite(message);
        adjustServerRandom(message);
        adjustExtensions(message);
        warnOnConflictingExtensions();
        if (!message.isTls13HelloRetryRequest()) {
            if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
                KeyShareStoreEntry keyShareStoreEntry = adjustKeyShareStoreEntry();
                adjustHandshakeTrafficSecrets(keyShareStoreEntry);
                if (context.getTalkingConnectionEndType() != context.getChooser().getConnectionEndType()) {
                    setServerRecordCipher();
                }
            }
            adjustPRF(message);
            if (context.hasSession(context.getChooser().getServerSessionId())) {
                LOGGER.info("Resuming Session");
                LOGGER.debug("Loading MasterSecret");
                Session session = context.getIdSession(context.getChooser().getServerSessionId());
                context.setMasterSecret(session.getMasterSecret());
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
            context.setSelectedCipherSuite(suite);
            LOGGER.debug("Set SelectedCipherSuite in Context to " + suite.name());
        } else {
            LOGGER.warn("Unknown CipherSuite, did not adjust Context");
        }
    }

    private void adjustServerRandom(ServerHelloMessage message) {
        context.setServerRandom(message.getRandom().getValue());
        LOGGER.debug("Set ServerRandom in Context to " + ArrayConverter.bytesToHexString(context.getServerRandom()));
    }

    private void adjustSelectedCompression(ServerHelloMessage message) {

        CompressionMethod method = null;
        if (message.getSelectedCompressionMethod() != null) {
            method = CompressionMethod.getCompressionMethod(message.getSelectedCompressionMethod().getValue());
        }

        if (method != null) {
            context.setSelectedCompressionMethod(method);
            LOGGER.debug("Set SelectedCompressionMethod in Context to " + method.name());
        } else {
            LOGGER.warn("Not adjusting CompressionMethod - Method is null!");
        }
    }

    private void adjustSelectedSessionID(ServerHelloMessage message) {
        byte[] sessionID = message.getSessionId().getValue();
        context.setServerSessionId(sessionID);
        LOGGER.debug("Set SessionID in Context to " + ArrayConverter.bytesToHexString(sessionID, false));
    }

    private void adjustSelectedProtocolVersion(ServerHelloMessage message) {
        ProtocolVersion version = null;

        if (message.getProtocolVersion() != null) {
            version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        }

        if (version != null) {
            context.setSelectedProtocolVersion(version);
            LOGGER.debug("Set SelectedProtocolVersion in Context to " + version.name());
        } else {
            LOGGER.warn("Did not Adjust ProtocolVersion since version is undefined "
                + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
        }
    }

    private void adjustPRF(ServerHelloMessage message) {
        Chooser chooser = context.getChooser();
        if (!chooser.getSelectedProtocolVersion().isSSL()) {
            context.setPrfAlgorithm(AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                chooser.getSelectedCipherSuite()));
        }
    }

    private void setServerRecordCipher() {
        context.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        LOGGER.debug("Setting cipher for server to use handshake secrets");
        KeySet serverKeySet = getTls13KeySet(context, context.getActiveServerKeySetType());

        if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            context.getRecordLayer()
                .updateDecryptionCipher(RecordCipherFactory.getRecordCipher(context, serverKeySet));
        } else {
            context.getRecordLayer()
                .updateEncryptionCipher(RecordCipherFactory.getRecordCipher(context, serverKeySet));
        }
    }

    private KeySet getTls13KeySet(TlsContext context, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            return KeySetGenerator.generateKeySet(context, this.context.getChooser().getSelectedProtocolVersion(),
                keySetType);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    @Override
    public void adjustContextAfterSerialize(ServerHelloMessage message) {
        if (context.getChooser().getSelectedProtocolVersion().isTLS13() && !message.isTls13HelloRetryRequest()) {
            setServerRecordCipher();
        }
    }

    private void adjustHandshakeTrafficSecrets(KeyShareStoreEntry keyShareStoreEntry) {
        HKDFAlgorithm hkdfAlgorithm =
            AlgorithmResolver.getHKDFAlgorithm(context.getChooser().getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(
            context.getChooser().getSelectedProtocolVersion(), context.getChooser().getSelectedCipherSuite());

        try {
            int macLength = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] psk = (context.getConfig().isUsePsk() || context.getPsk() != null)
                ? context.getChooser().getPsk() : new byte[macLength]; // use PSK if available
            byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], psk);
            byte[] saltHandshakeSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(), earlySecret,
                HKDFunction.DERIVED, new byte[0]);
            byte[] sharedSecret;
            BigInteger privateKey = context.getConfig().getKeySharePrivate();
            if (context.getChooser().getSelectedCipherSuite().isPWD()) {
                sharedSecret = computeSharedPWDSecret(keyShareStoreEntry);
            } else {
                sharedSecret = KeyShareCalculator.computeSharedSecret(keyShareStoreEntry.getGroup(), privateKey,
                    keyShareStoreEntry.getPublicKey());
                // This is a workaround for Tls1.3 InvalidCurve attacks
                if (context.getConfig().getDefaultPreMasterSecret().length > 0) {
                    LOGGER.debug("Using specified PMS instead of computed PMS");
                    sharedSecret = context.getConfig().getDefaultPreMasterSecret();
                }
            }
            byte[] handshakeSecret = HKDFunction.extract(hkdfAlgorithm, saltHandshakeSecret, sharedSecret);
            context.setHandshakeSecret(handshakeSecret);
            LOGGER.debug("Set handshakeSecret in Context to " + ArrayConverter.bytesToHexString(handshakeSecret));
            byte[] clientHandshakeTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                handshakeSecret, HKDFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET, context.getDigest().getRawBytes());
            context.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
            LOGGER.debug("Set clientHandshakeTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(clientHandshakeTrafficSecret));
            byte[] serverHandshakeTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                handshakeSecret, HKDFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET, context.getDigest().getRawBytes());
            context.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
            LOGGER.debug("Set serverHandshakeTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(serverHandshakeTrafficSecret));
        } catch (CryptoException | NoSuchAlgorithmException ex) {
            throw new AdjustmentException(ex);
        }
    }

    private byte[] computeSharedPWDSecret(KeyShareStoreEntry keyShare) throws CryptoException {
        Chooser chooser = context.getChooser();
        EllipticCurve curve = CurveFactory.getCurve(keyShare.getGroup());
        DragonFlyKeyShareEntryParser parser =
            new DragonFlyKeyShareEntryParser(new ByteArrayInputStream(keyShare.getPublicKey()), keyShare.getGroup());
        DragonFlyKeyShareEntry dragonFlyKeyShareEntry = new DragonFlyKeyShareEntry();
        parser.parse(dragonFlyKeyShareEntry);
        int curveSize = curve.getModulus().bitLength();
        Point keySharePoint =
            PointFormatter.fromRawFormat(keyShare.getGroup(), dragonFlyKeyShareEntry.getRawPublicKey());

        BigInteger scalar = dragonFlyKeyShareEntry.getScalar();
        Point passwordElement = PWDComputations.computePasswordElement(context.getChooser(), curve);
        BigInteger privateKeyScalar;
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            privateKeyScalar =
                new BigInteger(1, chooser.getConfig().getDefaultClientPWDPrivate()).mod(curve.getBasePointOrder());
        } else {
            privateKeyScalar =
                new BigInteger(1, chooser.getConfig().getDefaultServerPWDPrivate()).mod(curve.getBasePointOrder());
        }
        LOGGER.debug("Element: " + ArrayConverter.bytesToHexString(PointFormatter.toRawFormat(keySharePoint)));
        LOGGER.debug("Scalar: " + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(scalar)));

        Point sharedSecret =
            curve.mult(privateKeyScalar, curve.add(curve.mult(scalar, passwordElement), keySharePoint));
        return ArrayConverter.bigIntegerToByteArray(sharedSecret.getFieldX().getData(), curveSize / Bits.IN_A_BYTE,
            true);
    }

    private void adjustHelloRetryDigest(ServerHelloMessage message) {
        try {
            byte[] lastClientHello = context.getChooser().getLastClientHello();
            LOGGER.debug("Replacing current digest for Hello Retry Request using Client Hello: "
                + ArrayConverter.bytesToHexString(lastClientHello));

            DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13,
                context.getChooser().getSelectedCipherSuite());
            MessageDigest hash = MessageDigest.getInstance(algorithm.getJavaName());
            hash.update(lastClientHello);
            byte[] clientHelloHash = hash.digest();
            byte[] serverHelloBytes = message.getCompleteResultingMessage().getValue();

            context.getDigest().setRawBytes(HandshakeMessageType.MESSAGE_HASH.getArrayValue());
            context.getDigest()
                .append(ArrayConverter.intToBytes(clientHelloHash.length, HandshakeByteLength.MESSAGE_LENGTH_FIELD));
            context.getDigest().append(clientHelloHash);
            context.getDigest().append(serverHelloBytes);
            LOGGER.debug(
                "Complete resulting digest: " + ArrayConverter.bytesToHexString(context.getDigest().getRawBytes()));
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error(ex);
        }
    }

    private void warnOnConflictingExtensions() {
        if (context.getTalkingConnectionEndType() == context.getChooser().getMyConnectionPeer()) {
            // for TLS 1.3, this is handled in encrypted extensions
            if (!context.getChooser().getSelectedProtocolVersion().isTLS13()) {
                if (context.isExtensionNegotiated(ExtensionType.MAX_FRAGMENT_LENGTH)
                    && context.isExtensionNegotiated(ExtensionType.RECORD_SIZE_LIMIT)) {
                    // this is supposed to result in a fatal error, just warning for now
                    LOGGER.warn("Server sent max_fragment_length AND record_size_limit extensions");
                }
            }
        }
    }

    private KeyShareStoreEntry adjustKeyShareStoreEntry() {
        KeyShareStoreEntry selectedKeyShareStore;
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            selectedKeyShareStore = context.getChooser().getServerKeyShare();
        } else {
            Integer pos = null;
            for (KeyShareStoreEntry entry : context.getChooser().getClientKeyShares()) {
                if (Arrays.equals(entry.getGroup().getValue(),
                    context.getChooser().getServerKeyShare().getGroup().getValue())) {
                    pos = context.getChooser().getClientKeyShares().indexOf(entry);
                }
            }
            if (pos == null) {
                LOGGER.warn("Client did not send the KeyShareType we expected. Choosing first in his List");
                pos = 0;
            }

            selectedKeyShareStore = context.getChooser().getClientKeyShares().get(pos);
        }
        context.setSelectedGroup(selectedKeyShareStore.getGroup());

        if (selectedKeyShareStore.getGroup().isCurve()) {
            Point publicPoint;
            if (context.getChooser().getSelectedCipherSuite().isPWD()) {
                publicPoint = PointFormatter.fromRawFormat(selectedKeyShareStore.getGroup(),
                    selectedKeyShareStore.getPublicKey());
            } else {
                publicPoint = PointFormatter.formatFromByteArray(selectedKeyShareStore.getGroup(),
                    selectedKeyShareStore.getPublicKey());
            }
            context.setServerEcPublicKey(publicPoint);
        } else {
            context.setServerDhPublicKey(new BigInteger(selectedKeyShareStore.getPublicKey()));
        }

        return selectedKeyShareStore;
    }
}
