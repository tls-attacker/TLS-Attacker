/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.crypto.TlsMessageDigest;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TlsContext {

    // Default values
    private TlsConfig config;
    /**
     * master secret established during the handshake
     */
    private byte[] masterSecret = new byte[HandshakeByteLength.MASTER_SECRET];
    /**
     * premaster secret established during the handshake
     */
    private byte[] preMasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
    /**
     * client random, including unix time /** client random, including unix time
     */

    private byte[] clientRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * server random, including unix time
     */
    private byte[] serverRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * selected cipher suite
     */
    // Initially no ciphersuite is selected
    private CipherSuite selectedCipherSuite = null;

    /**
     * compression algorithm
     */
    private CompressionMethod compressionMethod;
    /**
     * session ID
     */
    // TODO should this not be 0?
    private byte[] sessionID = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * server certificate parsed from the server certificate message
     */
    private Certificate serverCertificate;
    /**
     * client certificate parsed from the client certificate message
     */
    private Certificate clientCertificate;
    /**
     * EC context containing information about public/private key agreements,
     * curves, and point formats
     */
    private TlsECContext ecContext;
    /**
     * Server DH parameters
     */
    private ServerDHParams serverDHParameters;
    /**
     * Server DH Private Key
     */
    private DHPrivateKeyParameters serverDHPrivateKeyParameters;
    /**
     * workflow trace containing all the messages exchanged during the
     * communication
     */
    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace;

    private TlsMessageDigest digest;

    private RecordHandler recordHandler;

    private TransportHandler transportHandler;

    private ConnectionEnd talkingConnectionEnd = ConnectionEnd.CLIENT;

    /**
     * DTLS Cookie
     */
    private byte[] dtlsHandshakeCookie = new byte[0];

    private ProtocolVersion selectedProtocolVersion;

    private ProtocolVersion highestClientProtocolVersion;

    private List<CipherSuite> clientSupportedCiphersuites;

    private List<CompressionMethod> clientSupportedCompressions;

    private List<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms;

    private HeartbeatMode heartbeatMode;

    private MaxFragmentLength maxFragmentLength;

    private SignatureAndHashAlgorithm selectedSigHashAlgorithm;

    private PublicKey clientPublicKey;

    private PublicKey serverPublicKey;

    // TODO does this make sense?
    public TlsContext() {
        digest = new TlsMessageDigest();
        ecContext = new TlsECContext();
        config = new TlsConfig();
        // init protocolVersion for records
        selectedProtocolVersion = config.getHighestProtocolVersion();
    }

    public TlsContext(TlsConfig config) {
        digest = new TlsMessageDigest();
        ecContext = new TlsECContext();
        this.config = config;
        // init protocolVersion for records
        selectedProtocolVersion = config.getHighestProtocolVersion();
    }

    public PublicKey getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(PublicKey clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(PublicKey serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public SignatureAndHashAlgorithm getSelectedSigHashAlgorithm() {
        return selectedSigHashAlgorithm;
    }

    public void setSelectedSigHashAlgorithm(SignatureAndHashAlgorithm selectedSigHashAlgorithm) {
        this.selectedSigHashAlgorithm = selectedSigHashAlgorithm;
    }

    public MaxFragmentLength getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(MaxFragmentLength maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
    }

    public HeartbeatMode getHeartbeatMode() {
        return heartbeatMode;
    }

    public void setHeartbeatMode(HeartbeatMode heartbeatMode) {
        this.heartbeatMode = heartbeatMode;
    }

    public List<CompressionMethod> getClientSupportedCompressions() {
        return Collections.unmodifiableList(clientSupportedCompressions);
    }

    public void setClientSupportedCompressions(List<CompressionMethod> clientSupportedCompressions) {
        this.clientSupportedCompressions = clientSupportedCompressions;
    }

    public List<CipherSuite> getClientSupportedCiphersuites() {
        return Collections.unmodifiableList(clientSupportedCiphersuites);
    }

    public void setClientSupportedCiphersuites(List<CipherSuite> clientSupportedCiphersuites) {
        this.clientSupportedCiphersuites = clientSupportedCiphersuites;
    }

    public List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms() {
        return Collections.unmodifiableList(serverSupportedSignatureAndHashAlgorithms);
    }

    public void setServerSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms) {
        this.serverSupportedSignatureAndHashAlgorithms = serverSupportedSignatureAndHashAlgorithms;
    }

    public ProtocolVersion getSelectedProtocolVersion() {
        return selectedProtocolVersion;
    }

    public void setSelectedProtocolVersion(ProtocolVersion selectedProtocolVersion) {
        this.selectedProtocolVersion = selectedProtocolVersion;
    }

    public ProtocolVersion getHighestClientProtocolVersion() {
        return highestClientProtocolVersion;
    }

    public void setHighestClientProtocolVersion(ProtocolVersion highestClientProtocolVersion) {
        this.highestClientProtocolVersion = highestClientProtocolVersion;
    }

    public ConnectionEnd getTalkingConnectionEnd() {
        return talkingConnectionEnd;
    }

    public void setTalkingConnectionEnd(ConnectionEnd talkingConnectionEnd) {
        this.talkingConnectionEnd = talkingConnectionEnd;
    }

    public TlsConfig getConfig() {
        return config;
    }

    public void initiliazeTlsMessageDigest() {
        try {
            DigestAlgorithm algorithm = AlgorithmResolver.getDigestAlgorithm(getSelectedProtocolVersion(),
                    selectedCipherSuite);
            digest.initializeDigestAlgorithm(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public byte[] getServerClientRandom() {
        return ArrayConverter.concatenate(serverRandom, clientRandom);
    }

    public CipherSuite getSelectedCipherSuite() {
        return selectedCipherSuite;
    }

    public void setMasterSecret(byte[] masterSecret) {
        this.masterSecret = masterSecret;
    }

    public void setSelectedCipherSuite(CipherSuite selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public byte[] getClientServerRandom() {
        return ArrayConverter.concatenate(clientRandom, serverRandom);
    }

    public byte[] getPreMasterSecret() {
        return preMasterSecret;
    }

    public void setPreMasterSecret(byte[] preMasterSecret) {
        this.preMasterSecret = preMasterSecret;
    }

    public byte[] getClientRandom() {
        return clientRandom;
    }

    public void setClientRandom(byte[] clientRandom) {
        this.clientRandom = clientRandom;
    }

    public byte[] getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = serverRandom;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    public void setCompressionMethod(CompressionMethod compressionMethod) {
        this.compressionMethod = compressionMethod;
    }

    public byte[] getSessionID() {
        return sessionID;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = sessionID;
    }

    public WorkflowTrace getWorkflowTrace() {
        return workflowTrace;
    }

    public void setWorkflowTrace(WorkflowTrace workflowTrace) {
        this.workflowTrace = workflowTrace;
    }

    public TlsECContext getEcContext() {
        return ecContext;
    }

    public void setEcContext(TlsECContext ecContext) {
        this.ecContext = ecContext;
    }

    public Certificate getServerCertificate() {
        return serverCertificate;
    }

    public void setServerCertificate(Certificate serverCertificate) {
        this.serverCertificate = serverCertificate;
    }

    public Certificate getClientCertificate() {
        return clientCertificate;
    }

    public void setClientCertificate(Certificate clientCertificate) {
        this.clientCertificate = clientCertificate;
    }

    public ServerDHParams getServerDHParameters() {
        return serverDHParameters;
    }

    public void setServerDHParameters(ServerDHParams serverDHParameters) {
        this.serverDHParameters = serverDHParameters;
    }

    public DHPrivateKeyParameters getServerDHPrivateKeyParameters() {
        return serverDHPrivateKeyParameters;
    }

    public void setServerDHPrivateKeyParameters(DHPrivateKeyParameters serverDHPrivateKeyParameters) {
        this.serverDHPrivateKeyParameters = serverDHPrivateKeyParameters;
    }

    public TlsMessageDigest getDigest() {
        return digest;
    }

    public void setDtlsHandshakeCookie(byte[] cookie) {
        this.dtlsHandshakeCookie = cookie;
    }

    public byte[] getDtlsHandshakeCookie() {
        return dtlsHandshakeCookie;
    }

    public TransportHandler getTransportHandler() {
        return transportHandler;
    }

    public void setTransportHandler(TransportHandler transportHandler) {
        this.transportHandler = transportHandler;
    }

    public RecordHandler getRecordHandler() {
        return recordHandler;
    }

    public void setRecordHandler(RecordHandler recordHandler) {
        this.recordHandler = recordHandler;
    }

    public PRFAlgorithm getPRFAlgorithm() {
        return AlgorithmResolver.getPRFAlgorithm(selectedProtocolVersion,selectedCipherSuite);
    }
}
