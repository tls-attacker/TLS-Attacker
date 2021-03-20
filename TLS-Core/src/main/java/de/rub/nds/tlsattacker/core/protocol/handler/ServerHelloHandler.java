/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.DragonFlyKeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.keyshare.DragonFlyKeyShareEntryParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.Session;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerHelloHandler extends HandshakeMessageHandler<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerHelloHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ServerHelloPreparator getPreparator(ServerHelloMessage message) {
        return new ServerHelloPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ServerHelloSerializer getSerializer(ServerHelloMessage message) {
        return new ServerHelloSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public ServerHelloParser getParser(byte[] message, int pointer) {
        return new ServerHelloParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
            tlsContext.getConfig());
    }

    @Override
    public void adjustTLSContext(ServerHelloMessage message) {
        adjustSelectedProtocolVersion(message);
        adjustSelectedCompression(message);
        adjustSelectedSessionID(message);
        adjustSelectedCipherSuite(message);
        adjustServerRandom(message);
        adjustExtensions(message);
        if (!message.isTls13HelloRetryRequest()) {
            if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
                adjustHandshakeTrafficSecrets();
                if (tlsContext.getTalkingConnectionEndType() != tlsContext.getChooser().getConnectionEndType()) {
                    setServerRecordCipher();
                }
            }
            adjustPRF(message);
            if (tlsContext.hasSession(tlsContext.getChooser().getServerSessionId())) {
                LOGGER.info("Resuming Session");
                LOGGER.debug("Loading MasterSecret");
                Session session = tlsContext.getSession(tlsContext.getChooser().getServerSessionId());
                tlsContext.setMasterSecret(session.getMasterSecret());
                setRecordCipher();
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
        LOGGER.debug("Set ServerRandom in Context to " + ArrayConverter.bytesToHexString(tlsContext.getServerRandom()));
    }

    private void adjustSelectedCompression(ServerHelloMessage message) {

        CompressionMethod method = null;
        if (message.getSelectedCompressionMethod() != null) {
            method = CompressionMethod.getCompressionMethod(message.getSelectedCompressionMethod().getValue());
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
        LOGGER.debug("Set SessionID in Context to " + ArrayConverter.bytesToHexString(sessionID, false));
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
            LOGGER.warn("Did not Adjust ProtocolVersion since version is undefined "
                + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
        }
    }

    private void adjustPRF(ServerHelloMessage message) {
        Chooser chooser = tlsContext.getChooser();
        if (!chooser.getSelectedProtocolVersion().isSSL()) {
            tlsContext.setPrfAlgorithm(AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(),
                chooser.getSelectedCipherSuite()));
        }
    }

    private void setRecordCipher() {
        KeySet keySet = getKeySet(tlsContext, Tls13KeySetType.NONE);
        LOGGER.debug("Setting new Cipher in RecordLayer");
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet);
        tlsContext.getRecordLayer().setRecordCipher(recordCipher);
    }

    private void setServerRecordCipher() {
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        LOGGER.debug("Setting cipher for server to use handshake secrets");
        KeySet serverKeySet = getKeySet(tlsContext, tlsContext.getActiveServerKeySetType());
        RecordCipher recordCipherServer = RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet,
            tlsContext.getChooser().getSelectedCipherSuite());
        tlsContext.getRecordLayer().setRecordCipher(recordCipherServer);

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setReadSequenceNumber(0);
            tlsContext.getRecordLayer().updateDecryptionCipher();
        } else {
            tlsContext.setWriteSequenceNumber(0);
            tlsContext.getRecordLayer().updateEncryptionCipher();
        }
    }

    private KeySet getKeySet(TlsContext context, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            return KeySetGenerator.generateKeySet(context, tlsContext.getChooser().getSelectedProtocolVersion(),
                keySetType);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(ServerHelloMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13() && !message.isTls13HelloRetryRequest()) {
            setServerRecordCipher();
        }
    }

    private void adjustHandshakeTrafficSecrets() {
        HKDFAlgorithm hkdfAlgorithm =
            AlgorithmResolver.getHKDFAlgorithm(tlsContext.getChooser().getSelectedCipherSuite());
        DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(
            tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext.getChooser().getSelectedCipherSuite());

        try {
            int macLength = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] psk = (tlsContext.getConfig().isUsePsk() || tlsContext.getPsk() != null)
                ? tlsContext.getChooser().getPsk() : new byte[macLength]; // use PSK if available
            byte[] earlySecret = HKDFunction.extract(hkdfAlgorithm, new byte[0], psk);
            byte[] saltHandshakeSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(), earlySecret,
                HKDFunction.DERIVED, new byte[0]);
            byte[] sharedSecret;
            if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
                if (tlsContext.getChooser().getSelectedCipherSuite().isPWD()) {
                    sharedSecret = computeSharedPWDSecret(tlsContext.getChooser().getServerKeyShare());
                } else {
                    sharedSecret = computeSharedSecret(tlsContext.getChooser().getServerKeyShare());

                    // This is a workaround for Tls1.3 InvalidCurve attacks
                    if (tlsContext.getConfig().getDefaultPreMasterSecret().length > 0) {
                        LOGGER.debug("Using specified PMS instead of computed PMS");
                        sharedSecret = tlsContext.getConfig().getDefaultPreMasterSecret();
                    }
                }
            } else {
                Integer pos = null;
                for (KeyShareStoreEntry entry : tlsContext.getChooser().getClientKeyShares()) {
                    if (Arrays.equals(entry.getGroup().getValue(),
                        tlsContext.getChooser().getServerKeyShare().getGroup().getValue())) {
                        pos = tlsContext.getChooser().getClientKeyShares().indexOf(entry);
                    }
                }
                if (pos == null) {
                    LOGGER.warn("Client did not send the KeyShareType we expected. Choosing first in his List");
                    pos = 0;
                }
                if (tlsContext.getChooser().getSelectedCipherSuite().isPWD()) {
                    sharedSecret = computeSharedPWDSecret(tlsContext.getChooser().getClientKeyShares().get(pos));
                } else {
                    sharedSecret = computeSharedSecret(tlsContext.getChooser().getClientKeyShares().get(pos));
                }
            }
            byte[] handshakeSecret = HKDFunction.extract(hkdfAlgorithm, saltHandshakeSecret, sharedSecret);
            tlsContext.setHandshakeSecret(handshakeSecret);
            LOGGER.debug("Set handshakeSecret in Context to " + ArrayConverter.bytesToHexString(handshakeSecret));
            byte[] clientHandshakeTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                handshakeSecret, HKDFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
            LOGGER.debug("Set clientHandshakeTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(clientHandshakeTrafficSecret));
            byte[] serverHandshakeTrafficSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                handshakeSecret, HKDFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET, tlsContext.getDigest().getRawBytes());
            tlsContext.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
            LOGGER.debug("Set serverHandshakeTrafficSecret in Context to "
                + ArrayConverter.bytesToHexString(serverHandshakeTrafficSecret));
        } catch (CryptoException | NoSuchAlgorithmException ex) {
            throw new AdjustmentException(ex);
        }
    }

    /**
     * Computes the shared secret for Elliptic Curves
     *
     * @return
     */
    private byte[] computeSharedSecret(KeyShareStoreEntry keyShare) {
        EllipticCurve curve = CurveFactory.getCurve(keyShare.getGroup());
        Point publicPoint = PointFormatter.formatFromByteArray(keyShare.getGroup(), keyShare.getPublicKey());
        tlsContext.setServerEcPublicKey(publicPoint);
        tlsContext.setSelectedGroup(keyShare.getGroup());
        BigInteger privateKey = tlsContext.getConfig().getKeySharePrivate();

        switch (keyShare.getGroup()) {
            case ECDH_X25519:
            case ECDH_X448:
                RFC7748Curve rfcCurve = (RFC7748Curve) curve;
                return rfcCurve.computeSharedSecretFromDecodedPoint(privateKey, publicPoint);
            case SECP160K1:
            case SECP160R1:
            case SECP160R2:
            case SECP192K1:
            case SECP192R1:
            case SECP224K1:
            case SECP224R1:
            case SECP256K1:
            case SECP256R1:
            case SECP384R1:
            case SECP521R1:
            case SECT163K1:
            case SECT163R1:
            case SECT163R2:
            case SECT193R1:
            case SECT193R2:
            case SECT233K1:
            case SECT233R1:
            case SECT239K1:
            case SECT283K1:
            case SECT283R1:
            case SECT409K1:
            case SECT409R1:
            case SECT571K1:
            case SECT571R1:
                Point sharedPoint = curve.mult(privateKey, publicPoint);
                int elementLength = ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus()).length;
                return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getFieldX().getData(), elementLength);
            default:
                throw new UnsupportedOperationException("KeyShare type " + keyShare.getGroup() + " is unsupported");
        }
    }

    private byte[] computeSharedPWDSecret(KeyShareStoreEntry keyShare) throws CryptoException {
        Chooser chooser = tlsContext.getChooser();
        EllipticCurve curve = CurveFactory.getCurve(keyShare.getGroup());
        DragonFlyKeyShareEntryParser parser =
            new DragonFlyKeyShareEntryParser(keyShare.getPublicKey(), keyShare.getGroup());
        DragonFlyKeyShareEntry dragonFlyKeyShareEntry = parser.parse();
        int curveSize = curve.getModulus().bitLength();
        Point keySharePoint =
            PointFormatter.fromRawFormat(keyShare.getGroup(), dragonFlyKeyShareEntry.getRawPublicKey());

        BigInteger scalar = dragonFlyKeyShareEntry.getScalar();
        Point passwordElement = PWDComputations.computePasswordElement(tlsContext.getChooser(), curve);
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
            byte[] lastClientHello = tlsContext.getChooser().getLastClientHello();
            LOGGER.debug("Replacing current digest for Hello Retry Request using Client Hello: "
                + ArrayConverter.bytesToHexString(lastClientHello));

            DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(ProtocolVersion.TLS13,
                tlsContext.getChooser().getSelectedCipherSuite());
            MessageDigest hash = MessageDigest.getInstance(algorithm.getJavaName());
            hash.update(lastClientHello);
            byte[] clientHelloHash = hash.digest();
            byte[] serverHelloBytes = message.getCompleteResultingMessage().getValue();

            tlsContext.getDigest().setRawBytes(HandshakeMessageType.MESSAGE_HASH.getArrayValue());
            tlsContext.getDigest()
                .append(ArrayConverter.intToBytes(clientHelloHash.length, HandshakeByteLength.MESSAGE_LENGTH_FIELD));
            tlsContext.getDigest().append(clientHelloHash);
            tlsContext.getDigest().append(serverHelloBytes);
            LOGGER.debug(
                "Complete resulting digest: " + ArrayConverter.bytesToHexString(tlsContext.getDigest().getRawBytes()));
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error(ex);
        }
    }
}
