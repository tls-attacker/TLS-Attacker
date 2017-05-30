/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.SNIEntry;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayer;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.security.PublicKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
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
    private byte[] masterSecret;
    /**
     * premaster secret established during the handshake
     */
    private byte[] preMasterSecret;
    /**
     * client random, including unix time /** client random, including unix time
     */
    private byte[] clientRandom;
    /**
     * server random, including unix time
     */
    private byte[] serverRandom;
    /**
     * selected cipher suite
     */
    // Initially no CipherSuite is selected
    private CipherSuite selectedCipherSuite = null;

    /**
     * compression algorithm
     */
    private CompressionMethod selectedCompressionMethod;
    /**
     * session ID
     */
    private byte[] sessionID;
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

    private MessageDigestCollector digest;

    private RecordLayer recordLayer;

    private TransportHandler transportHandler;

    private ConnectionEnd talkingConnectionEnd = ConnectionEnd.CLIENT;

    /**
     * DTLS Cookie
     */
    private byte[] dtlsHandshakeCookie;

    private ProtocolVersion selectedProtocolVersion;

    private ProtocolVersion highestClientProtocolVersion;

    private List<CipherSuite> clientSupportedCiphersuites;

    private List<CompressionMethod> clientSupportedCompressions;

    private List<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms;

    private List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms;

    private HeartbeatMode heartbeatMode;

    private MaxFragmentLength maxFragmentLength;

    private SignatureAndHashAlgorithm selectedSigHashAlgorithm;

    private PublicKey clientPublicKey;

    private PublicKey serverPublicKey;

    /**
     * EC public key parameters of the server
     */
    private ECPublicKeyParameters serverPublicKeyParameters;
    /**
     * supported named curves
     */
    private List<NamedCurve> clientNamedCurvesList;
    /**
     * supported client point formats
     */
    private List<ECPointFormat> clientPointFormatsList;

    private List<ECPointFormat> serverPointFormatsList;

    private boolean receivedFatalAlert = false;

    private List<ClientCertificateType> clientCertificateTypes;

    private byte[] distinguishedNames;

    private ProtocolVersion lastRecordVersion;

    private List<SNIEntry> clientSNIEntryList;

    private int sequenceNumber = 0;

    public TlsContext() {
        this(TlsConfig.createConfig());
    }

    public TlsContext(TlsConfig config) {
        digest = new MessageDigestCollector();
        this.config = config;
        // init lastRecordVersion for records
        clientCertificateTypes = new LinkedList<>();
        lastRecordVersion = config.getHighestProtocolVersion();
        selectedProtocolVersion = config.getHighestProtocolVersion();
    }

    public List<NamedCurve> getClientNamedCurvesList() {
        return clientNamedCurvesList;
    }

    public void setClientNamedCurvesList(List<NamedCurve> clientNamedCurvesList) {
        this.clientNamedCurvesList = clientNamedCurvesList;
    }

    public List<ECPointFormat> getServerPointFormatsList() {
        return serverPointFormatsList;
    }

    public void setServerPointFormatsList(List<ECPointFormat> serverPointFormatsList) {
        this.serverPointFormatsList = serverPointFormatsList;
    }

    public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
        return clientSupportedSignatureAndHashAlgorithms;
    }

    public void setClientSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms) {
        this.clientSupportedSignatureAndHashAlgorithms = clientSupportedSignatureAndHashAlgorithms;
    }

    public List<SNIEntry> getClientSNIEntryList() {
        return clientSNIEntryList;
    }

    public void setClientSNIEntryList(List<SNIEntry> clientSNIEntryList) {
        this.clientSNIEntryList = clientSNIEntryList;
    }

    public ProtocolVersion getLastRecordVersion() {
        return lastRecordVersion;
    }

    public void setLastRecordVersion(ProtocolVersion lastRecordVersion) {
        this.lastRecordVersion = lastRecordVersion;
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

    public ECPublicKeyParameters getServerPublicKeyParameters() {
        return serverPublicKeyParameters;
    }

    public void setServerECPublicKeyParameters(ECPublicKeyParameters serverPublicKeyParameters) {
        this.serverPublicKeyParameters = serverPublicKeyParameters;
    }

    public List<ECPointFormat> getClientPointFormatsList() {
        return clientPointFormatsList;
    }

    public void setClientPointFormatsList(List<ECPointFormat> clientPointFormatsList) {
        this.clientPointFormatsList = clientPointFormatsList;
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

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
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

    public byte[] getMasterSecret() {
        return masterSecret;
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

    public MessageDigestCollector getDigest() {
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

    public RecordLayer getRecordLayer() {
        return recordLayer;
    }

    public void setRecordLayer(RecordLayer recordLayer) {
        this.recordLayer = recordLayer;
    }

    public PRFAlgorithm getPRFAlgorithm() {
        return AlgorithmResolver.getPRFAlgorithm(selectedProtocolVersion, selectedCipherSuite);
    }
}
