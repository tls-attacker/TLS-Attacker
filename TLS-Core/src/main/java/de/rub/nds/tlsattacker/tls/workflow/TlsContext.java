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
import de.rub.nds.tlsattacker.tls.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
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
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;

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
    private byte[] masterSecret = new byte[0];
    /**
     * premaster secret established during the handshake
     */
    private byte[] preMasterSecret = new byte[0];
    /**
     * client random, including unix time /** client random, including unix time
     */
    private byte[] clientRandom = new byte[0];
    /**
     * server random, including unix time
     */
    private byte[] serverRandom = new byte[0];
    /**
     * selected cipher suite
     */
    // Initially no ciphersuite is selected
    private CipherSuite selectedCipherSuite = null;

    /**
     * compression algorithm
     */
    private CompressionMethod selectedCompressionMethod;
    /**
     * session ID
     */
    private byte[] sessionID = new byte[0];
    /**
     * server certificate parsed from the server certificate message
     */
    private Certificate serverCertificate;
    /**
     * client certificate parsed from the client certificate message
     */
    private Certificate clientCertificate;

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

    /**
     * EC public key parameters for EC handshakes
     */
    private ECPublicKeyParameters clientPublicKeyParameters;
    /**
     * EC private key parameters
     */
    private ECPrivateKeyParameters clientPrivateKeyParameters;
    /**
     * EC public key parameters of the server
     */
    private ECPublicKeyParameters serverPublicKeyParameters;
    /**
     * supported named curves
     */
    private NamedCurve[] clientNamedCurves;
    /**
     * supported server point formats
     */
    private ECPointFormat[] serverPointFormats;
    /**
     * supported client point formats
     */
    private ECPointFormat[] clientPointFormats;

    private boolean receivedFatalAlert = false;

    private List<ClientCertificateType> clientCertificateTypes;

    private byte[] distinguishedNames;

    // TODO does this make sense?
    public TlsContext() {
        digest = new TlsMessageDigest();
        config = new TlsConfig();
        clientCertificateTypes = new LinkedList<>();
        // init protocolVersion for records
        selectedProtocolVersion = config.getHighestProtocolVersion();
    }

    public TlsContext(TlsConfig config) {
        digest = new TlsMessageDigest();
        this.config = config;
        // init protocolVersion for records
        selectedProtocolVersion = config.getHighestProtocolVersion();
    }

    public byte[] getDistinguishedNames() {
        return distinguishedNames;
    }

    public void setDistinguishedNames(byte[] distinguishedNames) {
        this.distinguishedNames = distinguishedNames;
    }

    public List<ClientCertificateType> getClientCertificateTypes() {
        return clientCertificateTypes;
    }

    public void setClientCertificateTypes(List<ClientCertificateType> clientCertificateTypes) {
        this.clientCertificateTypes = clientCertificateTypes;
    }

    public boolean isReceivedFatalAlert() {
        return receivedFatalAlert;
    }

    public void setReceivedFatalAlert(boolean receivedFatalAlert) {
        this.receivedFatalAlert = receivedFatalAlert;
    }

    public ECPublicKeyParameters getClientPublicKeyParameters() {
        return clientPublicKeyParameters;
    }

    public void setClientPublicKeyParameters(ECPublicKeyParameters clientPublicKeyParameters) {
        this.clientPublicKeyParameters = clientPublicKeyParameters;
    }

    public ECPrivateKeyParameters getClientPrivateKeyParameters() {
        return clientPrivateKeyParameters;
    }

    public void setClientPrivateKeyParameters(ECPrivateKeyParameters clientPrivateKeyParameters) {
        this.clientPrivateKeyParameters = clientPrivateKeyParameters;
    }

    public ECPublicKeyParameters getServerPublicKeyParameters() {
        return serverPublicKeyParameters;
    }

    public void setServerPublicKeyParameters(ECPublicKeyParameters serverPublicKeyParameters) {
        this.serverPublicKeyParameters = serverPublicKeyParameters;
    }

    public NamedCurve[] getClientNamedCurves() {
        return clientNamedCurves;
    }

    public void setClientNamedCurves(NamedCurve[] clientNamedCurves) {
        this.clientNamedCurves = clientNamedCurves;
    }

    public ECPointFormat[] getServerPointFormats() {
        return serverPointFormats;
    }

    public void setServerPointFormats(ECPointFormat[] serverPointFormats) {
        this.serverPointFormats = serverPointFormats;
    }

    public ECPointFormat[] getClientPointFormats() {
        return clientPointFormats;
    }

    public void setClientPointFormats(ECPointFormat[] clientPointFormats) {
        this.clientPointFormats = clientPointFormats;
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
        if (clientSupportedCompressions == null) {
            return null;
        }
        return Collections.unmodifiableList(clientSupportedCompressions);
    }

    public void setClientSupportedCompressions(List<CompressionMethod> clientSupportedCompressions) {
        this.clientSupportedCompressions = clientSupportedCompressions;
    }

    public List<CipherSuite> getClientSupportedCiphersuites() {
        if (clientSupportedCompressions == null) {
            return null;
        }
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

    public CompressionMethod getSelectedCompressionMethod() {
        return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(CompressionMethod selectedCompressionMethod) {
        this.selectedCompressionMethod = selectedCompressionMethod;
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
        return AlgorithmResolver.getPRFAlgorithm(selectedProtocolVersion, selectedCipherSuite);
    }
}
