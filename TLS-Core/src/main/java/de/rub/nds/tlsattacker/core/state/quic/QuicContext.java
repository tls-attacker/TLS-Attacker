/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state.quic;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.Context;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicContext extends LayerContext {

    private static final Logger LOGGER = LogManager.getLogger();

    // TODO we may want to add config fields for these one day
    public static final byte[] DEFAULT_INITIAL_PACKET_TOKEN = new byte[] {};
    public static final int DEFAULT_INITIAL_PACKET_NUMBER = 0;

    private QuicVersion quicVersion;

    private byte[] firstDestinationConnectionId;
    private byte[] destinationConnectionId;
    private byte[] sourceConnectionId;
    private byte[] initialPacketToken = DEFAULT_INITIAL_PACKET_TOKEN;
    private QuicTransportParameters receivedTransportParameters;

    private byte[] initialSalt;
    private HKDFAlgorithm initialHKDFAlgorithm;
    private Cipher initialAeadCipher;
    private Cipher initalHeaderProtectionCipher;
    private CipherSuite initialCipherSuite;

    private HKDFAlgorithm zeroRTTHKDFAlgorithm;
    private Cipher zeroRTTAeadCipher;
    private Cipher zeroRTTHeaderProtectionCipher;
    private CipherSuite zeroRTTCipherSuite;

    private HKDFAlgorithm hkdfAlgorithm;
    private Cipher aeadCipher;
    private Cipher headerProtectionCipher;

    // Initial Keys
    private boolean initialSecretsInitialized;
    private byte[] initialSecret;
    private byte[] initialClientSecret;
    private byte[] initialServerSecret;

    private byte[] initialClientKey;
    private byte[] initialServerKey;

    private byte[] initialClientIv;
    private byte[] initialServerIv;

    private byte[] initialClientHeaderProtectionKey;
    private byte[] initialServerHeaderProtectionKey;

    // Handshake Keys
    private boolean handshakeSecretsInitialized;
    private byte[] handshakeClientSecret;
    private byte[] handshakeServerSecret;

    private byte[] handshakeClientKey;
    private byte[] handshakeServerKey;

    private byte[] handshakeClientIv;
    private byte[] handshakeServerIv;

    private byte[] handshakeClientHeaderProtectionKey;
    private byte[] handshakeServerHeaderProtectionKey;

    // Application Keys
    private boolean applicationSecretsInitialized;
    private byte[] applicationClientSecret;
    private byte[] applicationServerSecret;

    private byte[] applicationClientKey;
    private byte[] applicationServerKey;

    private byte[] applicationClientIv;
    private byte[] applicationServerIv;

    private byte[] applicationClientHeaderProtectionKey;
    private byte[] applicationServerHeaderProtectionKey;

    // 0-RTT Keys
    private boolean zeroRTTSecretsInitialized;
    private byte[] zeroRTTClientSecret;
    private byte[] zeroRTTServerSecret;

    private byte[] zeroRTTClientKey;
    private byte[] zeroRTTServerKey;

    private byte[] zeroRTTClientIv;
    private byte[] zeroRTTServerIv;

    private byte[] zeroRTTClientHeaderProtectionKey;
    private byte[] zeroRTTServerHeaderProtectionKey;

    private int initialPacketPacketNumber = DEFAULT_INITIAL_PACKET_NUMBER;
    private int handshakePacketPacketNumber = DEFAULT_INITIAL_PACKET_NUMBER;
    private int oneRTTPacketPacketNumber = DEFAULT_INITIAL_PACKET_NUMBER;

    private LinkedList<QuicPacketType> receivedPackets = new LinkedList<>();

    private final LinkedList<Integer> receivedInitialPacketNumbers = new LinkedList<>();
    private final LinkedList<Integer> receivedHandshakePacketNumbers = new LinkedList<>();
    private final LinkedList<Integer> receivedOneRTTPacketNumbers = new LinkedList<>();

    private List<byte[]> supportedVersions = new ArrayList<>();

    private ConnectionCloseFrame receivedConnectionCloseFrame;

    private byte[] pathChallengeData;

    public QuicContext(Context context) {
        super(context);
        init(context);
    }

    private void init(Context context) {
        this.quicVersion = context.getConfig().getQuicVersion();
        this.initialSalt = quicVersion.getInitialSalt();
        this.initialCipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        this.initialHKDFAlgorithm = AlgorithmResolver.getHKDFAlgorithm(getInitialCipherSuite());
        try {
            this.initialAeadCipher = Cipher.getInstance("AES/GCM/NoPadding");
            this.initalHeaderProtectionCipher = Cipher.getInstance("AES/ECB/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        this.sourceConnectionId = this.generateRandomConnectionId(16);
        this.firstDestinationConnectionId = this.generateRandomConnectionId(16);
        this.destinationConnectionId = this.firstDestinationConnectionId;
        try {
            QuicPacketCryptoComputations.calculateInitialSecrets(this);
        } catch (NoSuchAlgorithmException | CryptoException e) {
            LOGGER.error("Could not initialize initial secrets: ", e);
        }
    }

    private byte[] generateRandomConnectionId(int length) {
        byte[] arr = new byte[length];
        RandomHelper.getRandom().nextBytes(arr);
        return arr;
    }

    public void reset() {
        init(getContext());
        this.hkdfAlgorithm = null;
        this.aeadCipher = null;
        this.headerProtectionCipher = null;

        this.handshakeClientSecret = null;
        this.handshakeServerSecret = null;
        this.handshakeClientKey = null;
        this.handshakeServerKey = null;
        this.handshakeClientIv = null;
        this.handshakeServerIv = null;
        this.handshakeClientHeaderProtectionKey = null;
        this.handshakeServerHeaderProtectionKey = null;
        this.handshakeSecretsInitialized = false;

        this.applicationClientSecret = null;
        this.applicationServerSecret = null;
        this.applicationClientKey = null;
        this.applicationServerKey = null;
        this.applicationClientIv = null;
        this.applicationServerIv = null;
        this.applicationClientHeaderProtectionKey = null;
        this.applicationServerHeaderProtectionKey = null;
        this.applicationSecretsInitialized = false;

        this.zeroRTTClientSecret = null;
        this.zeroRTTServerSecret = null;
        this.zeroRTTClientKey = null;
        this.zeroRTTServerKey = null;
        this.zeroRTTClientIv = null;
        this.zeroRTTServerIv = null;
        this.zeroRTTClientHeaderProtectionKey = null;
        this.zeroRTTServerHeaderProtectionKey = null;
        this.zeroRTTSecretsInitialized = false;

        this.initialPacketPacketNumber = DEFAULT_INITIAL_PACKET_NUMBER;
        this.handshakePacketPacketNumber = DEFAULT_INITIAL_PACKET_NUMBER;
        this.oneRTTPacketPacketNumber = DEFAULT_INITIAL_PACKET_NUMBER;

        this.receivedPackets.clear();
        this.receivedInitialPacketNumbers.clear();
        this.receivedHandshakePacketNumbers.clear();
        this.receivedOneRTTPacketNumbers.clear();

        this.supportedVersions.clear();
        this.receivedConnectionCloseFrame = null;
    }

    public int getOneRTTPacketPacketNumber() {
        return oneRTTPacketPacketNumber;
    }

    public void setOneRTTPacketPacketNumber(int oneRTTPacketPacketNumber) {
        this.oneRTTPacketPacketNumber = oneRTTPacketPacketNumber;
    }

    public byte[] getFirstDestinationConnectionId() {
        return firstDestinationConnectionId;
    }

    public void setFirstDestinationConnectionId(byte[] firstDestinationConnectionId) {
        this.firstDestinationConnectionId = firstDestinationConnectionId;
    }

    public byte[] getDestinationConnectionId() {
        return destinationConnectionId;
    }

    public void setDestinationConnectionId(byte[] destinationConnectionId) {
        this.destinationConnectionId = destinationConnectionId;
    }

    public byte[] getSourceConnectionId() {
        return sourceConnectionId;
    }

    public void setSourceConnectionId(byte[] sourceConnectionId) {
        this.sourceConnectionId = sourceConnectionId;
    }

    public void setInitialHKDFAlgorithm(HKDFAlgorithm hkdfAlgorithm) {
        this.initialHKDFAlgorithm = hkdfAlgorithm;
    }

    public HKDFAlgorithm getInitialHKDFAlgorithm() {
        return initialHKDFAlgorithm;
    }

    public byte[] getInitialPacketToken() {
        return initialPacketToken;
    }

    public void setInitialPacketToken(byte[] initialPacketToken) {
        this.initialPacketToken = initialPacketToken;
    }

    public void addReceivedInitialPacketNumber(int packetNumber) {
        this.receivedInitialPacketNumbers.add(packetNumber);
        this.receivedInitialPacketNumbers.sort(Comparator.comparingInt(Integer::intValue));
    }

    public LinkedList<Integer> getReceivedInitialPacketNumbers() {
        return receivedInitialPacketNumbers;
    }

    public void addReceivedHandshakePacketNumber(int packetNumber) {
        this.receivedHandshakePacketNumbers.add(packetNumber);
        this.receivedHandshakePacketNumbers.sort(Comparator.comparingInt(Integer::intValue));
    }

    public LinkedList<Integer> getReceivedHandshakePacketNumbers() {
        return receivedHandshakePacketNumbers;
    }

    public void addReceivedOneRTTPacketNumber(int packetNumber) {
        this.receivedOneRTTPacketNumbers.add(packetNumber);
        this.receivedOneRTTPacketNumbers.sort(Comparator.comparingInt(Integer::intValue));
    }

    public LinkedList<Integer> getReceivedOneRTTPacketNumbers() {
        return receivedOneRTTPacketNumbers;
    }

    public int getHandshakePacketPacketNumber() {
        return handshakePacketPacketNumber;
    }

    public void setHandshakePacketPacketNumber(int handshakePacketPacketNumber) {
        this.handshakePacketPacketNumber = handshakePacketPacketNumber;
    }

    public int getInitialPacketPacketNumber() {
        return initialPacketPacketNumber;
    }

    public void setInitialPacketPacketNumber(int initialPacketPacketNumber) {
        this.initialPacketPacketNumber = initialPacketPacketNumber;
    }

    public byte[] getInitialSalt() {
        return initialSalt;
    }

    public CipherSuite getInitialCipherSuite() {
        return initialCipherSuite;
    }

    public Cipher getInitialAeadCipher() {
        return initialAeadCipher;
    }

    public QuicVersion getQuicVersion() {
        return quicVersion;
    }

    public QuicTransportParameters getReceivedTransportParameters() {
        return receivedTransportParameters;
    }

    public void setReceivedTransportParameters(
            QuicTransportParameters receivedTransportParameters) {
        this.receivedTransportParameters = receivedTransportParameters;
    }

    public LinkedList<QuicPacketType> getReceivedPackets() {
        return receivedPackets;
    }

    public void setReceivedPackets(LinkedList<QuicPacketType> receivedPackets) {
        this.receivedPackets = receivedPackets;
    }

    public boolean isInitialSecretsInitialized() {
        return initialSecretsInitialized;
    }

    public void setInitialSecretsInitialized(boolean initialSecretsInitialized) {
        this.initialSecretsInitialized = initialSecretsInitialized;
    }

    public byte[] getInitialSecret() {
        return initialSecret;
    }

    public void setInitialSecret(byte[] initialSecret) {
        this.initialSecret = initialSecret;
    }

    public byte[] getInitialClientSecret() {
        return initialClientSecret;
    }

    public void setInitialClientSecret(byte[] initialClientSecret) {
        this.initialClientSecret = initialClientSecret;
    }

    public byte[] getInitialServerSecret() {
        return initialServerSecret;
    }

    public void setInitialServerSecret(byte[] initialServerSecret) {
        this.initialServerSecret = initialServerSecret;
    }

    public byte[] getInitialClientKey() {
        return initialClientKey;
    }

    public void setInitialClientKey(byte[] initialClientKey) {
        this.initialClientKey = initialClientKey;
    }

    public byte[] getInitialServerKey() {
        return initialServerKey;
    }

    public void setInitialServerKey(byte[] initialServerKey) {
        this.initialServerKey = initialServerKey;
    }

    public byte[] getInitialClientIv() {
        return initialClientIv;
    }

    public void setInitialClientIv(byte[] initialClientIv) {
        this.initialClientIv = initialClientIv;
    }

    public byte[] getInitialServerIv() {
        return initialServerIv;
    }

    public void setInitialServerIv(byte[] initialServerIv) {
        this.initialServerIv = initialServerIv;
    }

    public byte[] getInitialClientHeaderProtectionKey() {
        return initialClientHeaderProtectionKey;
    }

    public void setInitialClientHeaderProtectionKey(byte[] initialClientHeaderProtectionKey) {
        this.initialClientHeaderProtectionKey = initialClientHeaderProtectionKey;
    }

    public byte[] getInitialServerHeaderProtectionKey() {
        return initialServerHeaderProtectionKey;
    }

    public void setInitialServerHeaderProtectionKey(byte[] initialServerHeaderProtectionKey) {
        this.initialServerHeaderProtectionKey = initialServerHeaderProtectionKey;
    }

    public boolean isHandshakeSecretsInitialized() {
        return handshakeSecretsInitialized;
    }

    public void setHandshakeSecretsInitialized(boolean handshakeSecretsInitialized) {
        this.handshakeSecretsInitialized = handshakeSecretsInitialized;
    }

    public byte[] getHandshakeClientSecret() {
        return handshakeClientSecret;
    }

    public void setHandshakeClientSecret(byte[] handshakeClientSecret) {
        this.handshakeClientSecret = handshakeClientSecret;
    }

    public byte[] getHandshakeServerSecret() {
        return handshakeServerSecret;
    }

    public void setHandshakeServerSecret(byte[] handshakeServerSecret) {
        this.handshakeServerSecret = handshakeServerSecret;
    }

    public byte[] getHandshakeClientKey() {
        return handshakeClientKey;
    }

    public void setHandshakeClientKey(byte[] handshakeClientKey) {
        this.handshakeClientKey = handshakeClientKey;
    }

    public byte[] getHandshakeServerKey() {
        return handshakeServerKey;
    }

    public void setHandshakeServerKey(byte[] handshakeServerKey) {
        this.handshakeServerKey = handshakeServerKey;
    }

    public byte[] getHandshakeClientIv() {
        return handshakeClientIv;
    }

    public void setHandshakeClientIv(byte[] handshakeClientIv) {
        this.handshakeClientIv = handshakeClientIv;
    }

    public byte[] getHandshakeServerIv() {
        return handshakeServerIv;
    }

    public void setHandshakeServerIv(byte[] handshakeServerIv) {
        this.handshakeServerIv = handshakeServerIv;
    }

    public byte[] getHandshakeClientHeaderProtectionKey() {
        return handshakeClientHeaderProtectionKey;
    }

    public void setHandshakeClientHeaderProtectionKey(byte[] handshakeClientHeaderProtectionKey) {
        this.handshakeClientHeaderProtectionKey = handshakeClientHeaderProtectionKey;
    }

    public byte[] getHandshakeServerHeaderProtectionKey() {
        return handshakeServerHeaderProtectionKey;
    }

    public void setHandshakeServerHeaderProtectionKey(byte[] handshakeServerHeaderProtectionKey) {
        this.handshakeServerHeaderProtectionKey = handshakeServerHeaderProtectionKey;
    }

    public boolean isApplicationSecretsInitialized() {
        return applicationSecretsInitialized;
    }

    public void setApplicationSecretsInitialized(boolean applicationSecretsInitialized) {
        this.applicationSecretsInitialized = applicationSecretsInitialized;
    }

    public byte[] getApplicationClientSecret() {
        return applicationClientSecret;
    }

    public void setApplicationClientSecret(byte[] applicationClientSecret) {
        this.applicationClientSecret = applicationClientSecret;
    }

    public byte[] getApplicationServerSecret() {
        return applicationServerSecret;
    }

    public void setApplicationServerSecret(byte[] applicationServerSecret) {
        this.applicationServerSecret = applicationServerSecret;
    }

    public byte[] getApplicationClientKey() {
        return applicationClientKey;
    }

    public void setApplicationClientKey(byte[] applicationClientKey) {
        this.applicationClientKey = applicationClientKey;
    }

    public byte[] getApplicationServerKey() {
        return applicationServerKey;
    }

    public void setApplicationServerKey(byte[] applicationServerKey) {
        this.applicationServerKey = applicationServerKey;
    }

    public byte[] getApplicationClientIv() {
        return applicationClientIv;
    }

    public void setApplicationClientIv(byte[] applicationClientIv) {
        this.applicationClientIv = applicationClientIv;
    }

    public byte[] getApplicationServerIv() {
        return applicationServerIv;
    }

    public void setApplicationServerIv(byte[] applicationServerIv) {
        this.applicationServerIv = applicationServerIv;
    }

    public byte[] getApplicationClientHeaderProtectionKey() {
        return applicationClientHeaderProtectionKey;
    }

    public void setApplicationClientHeaderProtectionKey(
            byte[] applicationClientHeaderProtectionKey) {
        this.applicationClientHeaderProtectionKey = applicationClientHeaderProtectionKey;
    }

    public byte[] getApplicationServerHeaderProtectionKey() {
        return applicationServerHeaderProtectionKey;
    }

    public void setApplicationServerHeaderProtectionKey(
            byte[] applicationServerHeaderProtectionKey) {
        this.applicationServerHeaderProtectionKey = applicationServerHeaderProtectionKey;
    }

    public boolean isZeroRTTSecretsInitialized() {
        return zeroRTTSecretsInitialized;
    }

    public void setZeroRTTSecretsInitialized(boolean zeroRTTSecretsInitialized) {
        this.zeroRTTSecretsInitialized = zeroRTTSecretsInitialized;
    }

    public byte[] getZeroRTTClientSecret() {
        return zeroRTTClientSecret;
    }

    public void setZeroRTTClientSecret(byte[] zeroRTTClientSecret) {
        this.zeroRTTClientSecret = zeroRTTClientSecret;
    }

    public byte[] getZeroRTTServerSecret() {
        return zeroRTTServerSecret;
    }

    public void setZeroRTTServerSecret(byte[] zeroRTTServerSecret) {
        this.zeroRTTServerSecret = zeroRTTServerSecret;
    }

    public byte[] getZeroRTTClientKey() {
        return zeroRTTClientKey;
    }

    public void setZeroRTTClientKey(byte[] zeroRTTClientKey) {
        this.zeroRTTClientKey = zeroRTTClientKey;
    }

    public byte[] getZeroRTTServerKey() {
        return zeroRTTServerKey;
    }

    public void setZeroRTTServerKey(byte[] zeroRTTServerKey) {
        this.zeroRTTServerKey = zeroRTTServerKey;
    }

    public byte[] getZeroRTTClientIv() {
        return zeroRTTClientIv;
    }

    public void setZeroRTTClientIv(byte[] zeroRTTClientIv) {
        this.zeroRTTClientIv = zeroRTTClientIv;
    }

    public byte[] getZeroRTTServerIv() {
        return zeroRTTServerIv;
    }

    public void setZeroRTTServerIv(byte[] zeroRTTServerIv) {
        this.zeroRTTServerIv = zeroRTTServerIv;
    }

    public byte[] getZeroRTTClientHeaderProtectionKey() {
        return zeroRTTClientHeaderProtectionKey;
    }

    public void setZeroRTTClientHeaderProtectionKey(byte[] zeroRTTClientHeaderProtectionKey) {
        this.zeroRTTClientHeaderProtectionKey = zeroRTTClientHeaderProtectionKey;
    }

    public byte[] getZeroRTTServerHeaderProtectionKey() {
        return zeroRTTServerHeaderProtectionKey;
    }

    public void setZeroRTTServerHeaderProtectionKey(byte[] zeroRTTServerHeaderProtectionKey) {
        this.zeroRTTServerHeaderProtectionKey = zeroRTTServerHeaderProtectionKey;
    }

    public HKDFAlgorithm getHkdfAlgorithm() {
        return hkdfAlgorithm;
    }

    public void setHkdfAlgorithm(HKDFAlgorithm hkdfAlgorithm) {
        this.hkdfAlgorithm = hkdfAlgorithm;
    }

    public Cipher getAeadCipher() {
        return aeadCipher;
    }

    public void setAeadCipher(Cipher aeadCipher) {
        this.aeadCipher = aeadCipher;
    }

    public Cipher getInitalHeaderProtectionCipher() {
        return initalHeaderProtectionCipher;
    }

    public void setInitalHeaderProtectionCipher(Cipher initalHeaderProtectionCipher) {
        this.initalHeaderProtectionCipher = initalHeaderProtectionCipher;
    }

    public Cipher getHeaderProtectionCipher() {
        return headerProtectionCipher;
    }

    public void setHeaderProtectionCipher(Cipher headerProtectionCipher) {
        this.headerProtectionCipher = headerProtectionCipher;
    }

    public List<byte[]> getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(List<byte[]> supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    public void addSupportedVersions(List<byte[]> supportedVersions) {
        this.supportedVersions.addAll(supportedVersions);
    }

    public ConnectionCloseFrame getReceivedConnectionCloseFrame() {
        return receivedConnectionCloseFrame;
    }

    public void setReceivedConnectionCloseFrame(ConnectionCloseFrame receivedConnectionCloseFrame) {
        this.receivedConnectionCloseFrame = receivedConnectionCloseFrame;
    }

    public HKDFAlgorithm getZeroRTTHKDFAlgorithm() {
        return zeroRTTHKDFAlgorithm;
    }

    public void setZeroRTTHKDFAlgorithm(HKDFAlgorithm zeroRTTHKDFAlgorithm) {
        this.zeroRTTHKDFAlgorithm = zeroRTTHKDFAlgorithm;
    }

    public Cipher getZeroRTTAeadCipher() {
        return zeroRTTAeadCipher;
    }

    public void setZeroRTTAeadCipher(Cipher zeroRTTAeadCipher) {
        this.zeroRTTAeadCipher = zeroRTTAeadCipher;
    }

    public Cipher getZeroRTTHeaderProtectionCipher() {
        return zeroRTTHeaderProtectionCipher;
    }

    public void setZeroRTTHeaderProtectionCipher(Cipher zeroRTTHeaderProtectionCipher) {
        this.zeroRTTHeaderProtectionCipher = zeroRTTHeaderProtectionCipher;
    }

    public CipherSuite getZeroRTTCipherSuite() {
        return zeroRTTCipherSuite;
    }

    public void setZeroRTTCipherSuite(CipherSuite zeroRTTCipherSuite) {
        this.zeroRTTCipherSuite = zeroRTTCipherSuite;
    }

    public byte[] getPathChallengeData() {
        return pathChallengeData;
    }

    public void setPathChallengeData(byte[] pathChallengeData) {
        this.pathChallengeData = pathChallengeData;
    }
}
