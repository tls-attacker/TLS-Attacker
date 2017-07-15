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
import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
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
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfiles;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.SNIEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayer;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.PublicKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.ServerDHParams;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class TlsContext {

    /**
     * TlsConfig which contains the configurations for everything TLS-Attacker
     * related
     */
    private TlsConfig config;
    /**
     * shared key established during the handshake
     */
    private byte[] handshakeSecret;
    /**
     * shared key established during the handshake
     */
    private byte[] clientHandshakeTrafficSecret;
    /**
     * shared key established during the handshake
     */
    private byte[] serverHandshakeTrafficSecret;
    /**
     * shared key established during the handshake
     */
    private byte[] clientApplicationTrafficSecret0;
    /**
     * shared key established during the handshake
     */
    private byte[] serverApplicationTrafficSecret0;
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
     * workflow trace containing all the messages exchanged during the
     * communication
     */
    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace;

    private MessageDigestCollector digest;

    private RecordLayer recordLayer;

    private TransportHandler transportHandler;

    private ConnectionEndType talkingConnectionEndType = ConnectionEndType.CLIENT;

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

    private boolean isCachedInfoExtensionClientState;

    private List<CachedObject> cachedInfoExtensionObjects;

    /**
     * These are the padding bytes as used in the padding extension.
     */
    private byte[] paddingExtensionBytes;

    /**
     * This is the session ticket of the SessionTicketTLS extension.
     */
    private byte[] sessionTicketTLS;

    /**
     * Is the extended master secret extension present?
     */
    private boolean isExtendedMasterSecretExtension;

    /**
     * This is the renegotiation info of the RenegotiationInfo extension.
     */
    private byte[] renegotiationInfo;
    /**
     * This is the requestContext from the CertificateRequest messsage in TLS
     * 1.3
     */
    private byte[] certificateRequestContext;
    /**
     * This is the timestamp of the SignedCertificateTimestamp extension
     */
    private byte[] signedCertificateTimestamp;

    /**
     * This is the request type of the CertificateStatusRequest extension
     */
    private CertificateStatusRequestType certificateStatusRequestExtensionRequestType;

    /**
     * This is the responder ID list of the CertificateStatusRequest extension
     */
    private byte[] certificateStatusRequestExtensionResponderIDList;

    /**
     * This is the request extension of the CertificateStatusRequest extension
     */
    private byte[] certificateStatusRequestExtensionRequestExtension;

    /**
     * This is the user identifier of the SRP extension
     */
    private byte[] secureRemotePasswordExtensionIdentifier;

    /**
     * These are the protection profiles of the SRTP extension
     */
    private List<SrtpProtectionProfiles> secureRealTimeTransportProtocolProtectionProfiles;

    /**
     * This is the master key identifier of the SRTP extension
     */
    private byte[] secureRealTimeProtocolMasterKeyIdentifier;

    /**
     * Is the truncated hmac extension present?
     */
    private boolean truncatedHmacExtensionIsPresent;

    /**
     * Is the encrypt then mac extension present?
     */
    private boolean encryptThenMacExtensionIsPresent;

    /**
     * User mapping extension hint type
     */
    private UserMappingExtensionHintType userMappingExtensionHintType;

    /**
     * Client authz extension data format list
     */
    private List<AuthzDataFormat> clientAuthzDataFormatList;

    /**
     * Server authz extension data format list
     */
    private List<AuthzDataFormat> serverAuthzDataFormatList;

    private PublicKey clientCertificatePublicKey;

    private PublicKey serverCertificatePublicKey;

    private ECPublicKeyParameters serverEcPublicKeyParameters;

    private ECPrivateKeyParameters serverEcPrivateKeyParameters;

    private DHPrivateKeyParameters serverDhPrivateKeyParameters;

    private DHPublicKeyParameters serverDhPublicKeyParameters;

    private ServerDHParams serverDHParameters;

    private List<NamedCurve> clientNamedCurvesList;

    private List<ECPointFormat> clientPointFormatsList;

    private List<ECPointFormat> serverPointFormatsList;

    private boolean receivedFatalAlert = false;

    private boolean encryptActive = false;
    /**
     * TLS 1.3, update keys for application data
     */
    private boolean updateKeys = false;

    private List<ClientCertificateType> clientCertificateTypes;

    private byte[] distinguishedNames;

    private ProtocolVersion lastRecordVersion;

    private List<SNIEntry> clientSNIEntryList;

    private List<KSEntry> clientKSEntryList;

    private KSEntry serverKSEntry;

    private int sequenceNumber = 0;

    /**
     * supported protocol versions
     */
    private List<ProtocolVersion> clientSupportedProtocolVersions;

    private TokenBindingVersion tokenBindingVersion;

    private List<TokenBindingKeyParameters> tokenBindingKeyParameters;

    private byte[] AlpnAnnouncedProtocols;

    private List<CertificateType> certificateTypeDesiredTypes;

    private List<CertificateType> serverCertificateTypeDesiredTypes;

    private List<CertificateType> clientCertificateTypeDesiredTypes;

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

    public List<ProtocolVersion> getClientSupportedProtocolVersions() {
        return clientSupportedProtocolVersions;
    }

    public void setClientSupportedProtocolVersions(List<ProtocolVersion> clientSupportedProtocolVersions) {
        this.clientSupportedProtocolVersions = clientSupportedProtocolVersions;
    }

    public DHPublicKeyParameters getServerDhPublicKeyParameters() {
        return serverDhPublicKeyParameters;
    }

    public void setServerDhPublicKeyParameters(DHPublicKeyParameters serverDhPublicKeyParameters) {
        this.serverDhPublicKeyParameters = serverDhPublicKeyParameters;
    }

    public ECPrivateKeyParameters getServerEcPrivateKeyParameters() {
        return serverEcPrivateKeyParameters;
    }

    public void setServerEcPrivateKeyParameters(ECPrivateKeyParameters serverEcPrivateKeyParameters) {
        this.serverEcPrivateKeyParameters = serverEcPrivateKeyParameters;
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

    public boolean isEncryptActive() {
        return encryptActive;
    }

    public void setEncryptActive(boolean encryptActive) {
        this.encryptActive = encryptActive;
    }

    public boolean isUpdateKeys() {
        return updateKeys;
    }

    public void setUpdateKeys(boolean updateKeys) {
        this.updateKeys = updateKeys;
    }

    public ECPublicKeyParameters getServerEcPublicKeyParameters() {
        return serverEcPublicKeyParameters;
    }

    public void setServerECPublicKeyParameters(ECPublicKeyParameters serverPublicKeyParameters) {
        this.serverEcPublicKeyParameters = serverPublicKeyParameters;
    }

    public List<ECPointFormat> getClientPointFormatsList() {
        return clientPointFormatsList;
    }

    public void setClientPointFormatsList(List<ECPointFormat> clientPointFormatsList) {
        this.clientPointFormatsList = clientPointFormatsList;
    }

    public PublicKey getClientCertificatePublicKey() {
        return clientCertificatePublicKey;
    }

    public void setClientCertificatePublicKey(PublicKey clientCertificatePublicKey) {
        this.clientCertificatePublicKey = clientCertificatePublicKey;
    }

    public PublicKey getServerCertificatePublicKey() {
        return serverCertificatePublicKey;
    }

    public void setServerCertificatePublicKey(PublicKey serverCertificatePublicKey) {
        this.serverCertificatePublicKey = serverCertificatePublicKey;
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

    public byte[] getPaddingExtensionBytes() {
        return paddingExtensionBytes;
    }

    public void setPaddingExtensionBytes(byte[] paddingExtensionBytes) {
        this.paddingExtensionBytes = paddingExtensionBytes;
    }

    public boolean isExtendedMasterSecretExtension() {
        return isExtendedMasterSecretExtension;
    }

    public void setIsExtendedMasterSecretExtension(boolean isExtendedMasterSecretExtension) {
        this.isExtendedMasterSecretExtension = isExtendedMasterSecretExtension;
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
        if (clientSupportedCiphersuites == null) {
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

    public ConnectionEndType getTalkingConnectionEndType() {
        return talkingConnectionEndType;
    }

    public void setTalkingConnectionEndType(ConnectionEndType talkingConnectionEndType) {
        this.talkingConnectionEndType = talkingConnectionEndType;
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

    public DHPrivateKeyParameters getServerDhPrivateKeyParameters() {
        return serverDhPrivateKeyParameters;
    }

    public void setServerDhPrivateKeyParameters(DHPrivateKeyParameters serverDhPrivateKeyParameters) {
        this.serverDhPrivateKeyParameters = serverDhPrivateKeyParameters;
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

    public byte[] getClientHandshakeTrafficSecret() {
        return clientHandshakeTrafficSecret;
    }

    public void setClientHandshakeTrafficSecret(byte[] clientHandshakeTrafficSecret) {
        this.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret;
    }

    public byte[] getServerHandshakeTrafficSecret() {
        return serverHandshakeTrafficSecret;
    }

    public void setServerHandshakeTrafficSecret(byte[] serverHandshakeTrafficSecret) {
        this.serverHandshakeTrafficSecret = serverHandshakeTrafficSecret;
    }

    public byte[] getClientApplicationTrafficSecret0() {
        return clientApplicationTrafficSecret0;
    }

    public void setClientApplicationTrafficSecret0(byte[] clientApplicationTrafficSecret0) {
        this.clientApplicationTrafficSecret0 = clientApplicationTrafficSecret0;
    }

    public byte[] getServerApplicationTrafficSecret0() {
        return serverApplicationTrafficSecret0;
    }

    public void setServerApplicationTrafficSecret0(byte[] serverApplicationTrafficSecret0) {
        this.serverApplicationTrafficSecret0 = serverApplicationTrafficSecret0;
    }

    public byte[] getHandshakeSecret() {
        return handshakeSecret;
    }

    public void setHandshakeSecret(byte[] handshakeSecret) {
        this.handshakeSecret = handshakeSecret;
    }

    public List<KSEntry> getClientKSEntryList() {
        return clientKSEntryList;
    }

    public void setClientKSEntryList(List<KSEntry> clientKSEntryList) {
        this.clientKSEntryList = clientKSEntryList;
    }

    public KSEntry getServerKSEntry() {
        return serverKSEntry;
    }

    public void setServerKSEntry(KSEntry serverKSEntry) {
        this.serverKSEntry = serverKSEntry;
    }

    public byte[] getSessionTicketTLS() {
        return sessionTicketTLS;
    }

    public void setSessionTicketTLS(byte[] sessionTicketTLS) {
        this.sessionTicketTLS = sessionTicketTLS;
    }

    public byte[] getSignedCertificateTimestamp() {
        return signedCertificateTimestamp;
    }

    public void setSignedCertificateTimestamp(byte[] signedCertificateTimestamp) {
        this.signedCertificateTimestamp = signedCertificateTimestamp;
    }

    public byte[] getRenegotiationInfo() {
        return renegotiationInfo;
    }

    public void setRenegotiationInfo(byte[] renegotiationInfo) {
        this.renegotiationInfo = renegotiationInfo;
    }

    public TokenBindingVersion getTokenBindingVersion() {
        return tokenBindingVersion;
    }

    public void setTokenBindingVersion(TokenBindingVersion tokenBindingVersion) {
        this.tokenBindingVersion = tokenBindingVersion;
    }

    public List getTokenBindingKeyParameters() {
        return tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(List tokenBindingKeyParameters) {
        this.tokenBindingKeyParameters = tokenBindingKeyParameters;
    }

    public CertificateStatusRequestType getCertificateStatusRequestExtensionRequestType() {
        return certificateStatusRequestExtensionRequestType;
    }

    public void setCertificateStatusRequestExtensionRequestType(
            CertificateStatusRequestType certificateStatusRequestExtensionRequestType) {
        this.certificateStatusRequestExtensionRequestType = certificateStatusRequestExtensionRequestType;
    }

    public byte[] getCertificateStatusRequestExtensionResponderIDList() {
        return certificateStatusRequestExtensionResponderIDList;
    }

    public void setCertificateStatusRequestExtensionResponderIDList(
            byte[] certificateStatusRequestExtensionResponderIDList) {
        this.certificateStatusRequestExtensionResponderIDList = certificateStatusRequestExtensionResponderIDList;
    }

    public byte[] getCertificateStatusRequestExtensionRequestExtension() {
        return certificateStatusRequestExtensionRequestExtension;
    }

    public void setCertificateStatusRequestExtensionRequestExtension(
            byte[] certificateStatusRequestExtensionRequestExtension) {
        this.certificateStatusRequestExtensionRequestExtension = certificateStatusRequestExtensionRequestExtension;
    }

    public byte[] getAlpnAnnouncedProtocols() {
        return AlpnAnnouncedProtocols;
    }

    public void setAlpnAnnouncedProtocols(byte[] AlpnAnnouncedProtocols) {
        this.AlpnAnnouncedProtocols = AlpnAnnouncedProtocols;
    }

    public byte[] getSecureRemotePasswordExtensionIdentifier() {
        return secureRemotePasswordExtensionIdentifier;
    }

    public void setSecureRemotePasswordExtensionIdentifier(byte[] secureRemotePasswordExtensionIdentifier) {
        this.secureRemotePasswordExtensionIdentifier = secureRemotePasswordExtensionIdentifier;
    }

    public List<SrtpProtectionProfiles> getSecureRealTimeTransportProtocolProtectionProfiles() {
        return secureRealTimeTransportProtocolProtectionProfiles;
    }

    public void setSecureRealTimeTransportProtocolProtectionProfiles(
            List<SrtpProtectionProfiles> secureRealTimeTransportProtocolProtectionProfiles) {
        this.secureRealTimeTransportProtocolProtectionProfiles = secureRealTimeTransportProtocolProtectionProfiles;
    }

    public byte[] getSecureRealTimeProtocolMasterKeyIdentifier() {
        return secureRealTimeProtocolMasterKeyIdentifier;
    }

    public void setSecureRealTimeProtocolMasterKeyIdentifier(byte[] secureRealTimeProtocolMasterKeyIdentifier) {
        this.secureRealTimeProtocolMasterKeyIdentifier = secureRealTimeProtocolMasterKeyIdentifier;
    }

    public boolean isTruncatedHmacExtensionIsPresent() {
        return truncatedHmacExtensionIsPresent;
    }

    public void setTruncatedHmacExtensionIsPresent(boolean truncatedHmacExtensionIsPresent) {
        this.truncatedHmacExtensionIsPresent = truncatedHmacExtensionIsPresent;
    }

    public UserMappingExtensionHintType getUserMappingExtensionHintType() {
        return userMappingExtensionHintType;
    }

    public void setUserMappingExtensionHintType(UserMappingExtensionHintType userMappingExtensionHintType) {
        this.userMappingExtensionHintType = userMappingExtensionHintType;
    }

    public List<CertificateType> getCertificateTypeDesiredTypes() {
        return certificateTypeDesiredTypes;
    }

    public void setCertificateTypeDesiredTypes(List<CertificateType> certificateTypeDesiredTypes) {
        this.certificateTypeDesiredTypes = certificateTypeDesiredTypes;
    }

    public List<AuthzDataFormat> getClientAuthzDataFormatList() {
        return clientAuthzDataFormatList;
    }

    public void setClientAuthzDataFormatList(List<AuthzDataFormat> clientAuthzDataFormatList) {
        this.clientAuthzDataFormatList = clientAuthzDataFormatList;
    }

    public List<AuthzDataFormat> getServerAuthzDataFormatList() {
        return serverAuthzDataFormatList;
    }

    public void setServerAuthzDataFormatList(List<AuthzDataFormat> serverAuthzDataFormatList) {
        this.serverAuthzDataFormatList = serverAuthzDataFormatList;
    }

    public byte[] getCertificateRequestContext() {
        return certificateRequestContext;
    }

    public void setCertificateRequestContext(byte[] certificateRequestContext) {
        this.certificateRequestContext = certificateRequestContext;
    }

    public List<CertificateType> getClientCertificateTypeDesiredTypes() {
        return clientCertificateTypeDesiredTypes;
    }

    public void setClientCertificateTypeDesiredTypes(List<CertificateType> clientCertificateTypeDesiredTypes) {
        this.clientCertificateTypeDesiredTypes = clientCertificateTypeDesiredTypes;
    }

    public List<CertificateType> getServerCertificateTypeDesiredTypes() {
        return serverCertificateTypeDesiredTypes;
    }

    public void setServerCertificateTypeDesiredTypes(List<CertificateType> serverCertificateTypeDesiredTypes) {
        this.serverCertificateTypeDesiredTypes = serverCertificateTypeDesiredTypes;
    }

    public boolean isEncryptThenMacExtensionIsPresent() {
        return encryptThenMacExtensionIsPresent;
    }

    public void setEncryptThenMacExtensionIsPresent(boolean encryptThenMacExtensionIsPresent) {
        this.encryptThenMacExtensionIsPresent = encryptThenMacExtensionIsPresent;
    }

    public boolean isIsCachedInfoExtensionClientState() {
        return isCachedInfoExtensionClientState;
    }

    public void setIsCachedInfoExtensionClientState(boolean isCachedInfoExtensionClientState) {
        this.isCachedInfoExtensionClientState = isCachedInfoExtensionClientState;
    }

    public List<CachedObject> getCachedInfoExtensionObjects() {
        return cachedInfoExtensionObjects;
    }

    public void setCachedInfoExtensionObjects(List<CachedObject> cachedInfoExtensionObjects) {
        this.cachedInfoExtensionObjects = cachedInfoExtensionObjects;
    }

}
