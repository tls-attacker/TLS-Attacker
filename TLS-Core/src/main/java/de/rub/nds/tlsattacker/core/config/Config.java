/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Config implements Serializable {
    public static Config createConfig() {
        InputStream stream = Config.class.getResourceAsStream("/default_config.xml");
        return ConfigIO.read(stream);
    }

    public static Config createConfig(File f) {
        return ConfigIO.read(f);
    }

    public static Config createConfig(InputStream stream) {
        return ConfigIO.read(stream);
    }

    /**
     * Default value for ProtocolVerionFields
     */
    private ProtocolVersion highestProtocolVersion = ProtocolVersion.TLS12;

    /**
     * Indicates which ConnectionEndType we are
     */
    private ConnectionEndType connectionEndType = ConnectionEndType.CLIENT;

    /**
     * The Workflow Trace that should be executed
     */
    private WorkflowTrace workflowTrace = null;

    /**
     * Keystore for storing client / server certificates
     */
    @XmlTransient
    private KeyStore keyStore = null;

    private String keyStoreFile = null;

    /**
     * Alias for the used key in the Keystore
     */
    private String alias = "default";
    /**
     * keystore password
     */
    private String password = "password";
    /**
     * host to connect
     */
    @XmlTransient
    private String host = "127.0.0.1";
    /**
     * If default generated WorkflowTraces should contain client Authentication
     */
    private boolean clientAuthentication = false;
    /**
     * If default generated WorkflowTraces should contain SessionResumption
     */
    private boolean sessionResumption = false;
    /**
     * If default generated WorkflowTraces should contain Renegotiation
     */
    private boolean renegotiation = false;
    /**
     * Which Signature and Hash algorithms we support
     */
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;
    /**
     * If we are in Fuzzing mode, eg ignore error and try to proceed as good as
     * possible
     */
    private boolean fuzzingMode = false;
    /**
     * Which Ciphersuites we support by default
     */
    private List<CipherSuite> supportedCiphersuites;
    /**
     * Which compression methods we support by default
     */
    private List<CompressionMethod> supportedCompressionMethods;
    /**
     * If we are a dynamic workflow //TODO implement
     */
    private boolean dynamicWorkflow = false;
    /**
     * Supported ECPointFormats by default
     */
    private List<ECPointFormat> pointFormats;
    /**
     * Supported namedCurves by default
     */
    private List<NamedCurve> namedCurves;
    /**
     * Which heartBeat mode we are in
     */
    private HeartbeatMode heartbeatMode = HeartbeatMode.PEER_ALLOWED_TO_SEND;
    /**
     * Hostname in SNI Extension
     */
    private String sniHostname = "localhost";
    /**
     * SNI HostnameType
     */
    private NameType sniType = NameType.HOST_NAME;
    /**
     * Should we terminate the connection on a wrong SNI ?
     */
    private boolean sniHostnameFatal = false;
    /**
     * Server port used
     */
    private int port = 443;
    /**
     * MaxFragmentLength in MaxFragmentLengthExtension
     */
    private MaxFragmentLength maxFragmentLength = MaxFragmentLength.TWO_9;
    /**
     * SessionTLSTicket for the SessionTLSTicketExtension. It's an empty session
     * ticket since we initiate a new connection.
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] TLSSessionTicket = new byte[0];
    /**
     * Renegotiation info for the RenegotiationInfo extension. It's an empty
     * info since we initiate a new connection.
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] renegotiationInfo = new byte[0];
    /**
     * SignedCertificateTimestamp for the SignedCertificateTimestampExtension.
     * It's an emty timestamp, since the server sends it.
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] signedCertificateTimestamp = new byte[0];
    /**
     * TokenBinding default version. To be defined later.
     */
    private TokenBindingVersion tokenBindingVersion = TokenBindingVersion.DRAFT_13;
    /**
     * Default TokenBinding Key Parameters.
     */
    private TokenBindingKeyParameters[] tokenBindingKeyParameters = { TokenBindingKeyParameters.RSA2048_PKCS1_5,
            TokenBindingKeyParameters.RSA2048_PSS, TokenBindingKeyParameters.ECDSAP256 };
    /**
     * Default Timeout we wait for TLSMessages
     */
    private int tlsTimeout = 400;
    /**
     * Default Timeout for the Connection
     */
    private int timeout = 1000;
    /**
     * Transporthandler Type that shall be used
     */
    private TransportHandlerType transportHandlerType = TransportHandlerType.TCP;
    /**
     * If the workflow should be verified //TODO ???
     */
    private boolean verifyWorkflow = false;
    /**
     * If we should use a workflow trace specified in File
     */
    private String workflowInput;
    /**
     * If we should output an executed workflowtrace to a specified file
     */
    private String workflowOutput;
    /**
     * The Type of workflow trace that should be generated
     */
    private WorkflowTraceType workflowTraceType;
    /**
     * If the Default generated workflowtrace should contain Application data
     * send by servers
     */
    private boolean serverSendsApplicationData = false;
    /**
     * If we generate ClientHello with the ECPointFormat extension
     */
    private boolean addECPointFormatExtension = true;
    /**
     * If we generate ClientHello with the EllipticCurve extension
     */
    private boolean addEllipticCurveExtension = true;
    /**
     * If we generate ClientHello with the Heartbeat extension
     */
    private boolean addHeartbeatExtension = false;
    /**
     * If we generate ClientHello with the MaxFragmentLength extension
     */
    private boolean addMaxFragmentLengthExtenstion = false;
    /**
     * If we generate ClientHello with the ServerNameIndication extension
     */
    private boolean addServerNameIndicationExtension = false;
    /**
     * If we generate ClientHello with the SignatureAndHashAlgorithm extension
     */
    private boolean addSignatureAndHashAlgrorithmsExtension = false;
    /**
     * If we generate ClientHello with the Padding extension
     */
    private boolean addPaddingExtension = false;
    /**
     * If we generate ClientHello with the ExtendedMasterSecret extension
     */
    private boolean addExtendedMasterSecretExtension = false;
    /**
     * If we generate ClientHello with the SessionTicketTLS extension
     */
    private boolean addSessionTicketTLSExtension = false;
    /**
     * If we generate ClientHello with SignedCertificateTimestamp extension
     */
    private boolean addSignedCertificateTimestampExtension = false;
    /**
     * If we generate ClientHello with RenegotiationInfo extension
     */
    private boolean addRenegotiationInfoExtension = false;
    /**
     * If we generate ClientHello with TokenBinding extension.
     */
    private boolean addTokenBindingExtension = false;

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] sessionId = new byte[0];
    /**
     * If set to true, timestamps will be updated upon execution of a
     * workflowTrace
     */
    private boolean updateTimestamps = true;
    /**
     * The Certificate we initialize CertificateMessages with
     */
    @XmlTransient
    private Certificate ourCertificate;

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] distinguishedNames = new byte[0];

    private boolean enforceSettings = false;

    private boolean doDTLSRetransmits = false;
    /**
     * Fixed DH modulus used in Server Key Exchange
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] fixedDHModulus = ArrayConverter
            .hexStringToByteArray("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc"
                    + "74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d"
                    + "51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24"
                    + "117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83"
                    + "655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca1821"
                    + "7c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695"
                    + "5817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff");
    /**
     * Fixed DH g value used in Server Key Exchange
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] fixedDHg = { 0x02 };

    private String defaultApplicationMessageData = "Test";

    @XmlTransient
    private PrivateKey privateKey;

    /**
     * If this is set TLS-Attacker only waits for the expected messages in the
     * ReceiveActions This is interesting for DTLS since this prevents the
     * server from retransmitting
     */
    private boolean waitOnlyForExpectedDTLS = true;

    private List<ClientCertificateType> clientCertificateTypes;

    /**
     * max payload length used in our application (not set by the spec)
     */
    private int heartbeatPayloadLength = 256;

    /**
     * according to the specification, the min padding length is 16
     */
    private int heartbeatMinPaddingLength = 16;

    /**
     * max padding length used in our application (not set by the spec)
     */
    private int heartbeatMaxPaddingLength = 256;

    /**
     * How long should our DTLSCookies be by default
     */
    private int defaultDTLSCookieLength = 6;

    /**
     * How much data we should put into a record by default
     */
    private int defaultMaxRecordData = 1048576;

    /**
     * How much padding bytes should be send by default
     */
    private byte[] defaultPaddingExtensionBytes = new byte[] { 0, 0, 0, 0, 0, 0 };

    // Switch between TLS and DTLS execution
    private ExecutorType executorType = ExecutorType.TLS;

    /**
     * Does not mix messages with different message types in a single record
     */
    private boolean flushOnMessageTypeChange = true;

    /**
     * If there is not enough space in the configured records, new records are
     * dynamically added if not set, protocolmessage bytes that wont fit are
     * discarded
     */
    private boolean createRecordsDynamically = true;
    /**
     * When "Null" records are configured to be send, every message will be sent
     * in atleast one individual record
     */
    private boolean createIndividualRecords = true;

    /**
     * Which recordLayer should be used
     */
    private RecordLayerType recordLayerType = RecordLayerType.RECORD;

    /**
     * If this value is set the default workflowExecutor will remove all runtime
     * values from the workflow trace and will only keep the relevant
     * information
     */
    private boolean stripWorkflowtracesBeforeSaving = false;

    /**
     * TLS-Attacker will not try to receive additional messages after the
     * configured number of messages has been received
     */
    private boolean quickReceive = true;

    /**
     * If the WorkflowExecutor should take care of the connection opening
     */
    private boolean workflowExecutorShouldOpen = true;

    /**
     * If the WorkflowExecutor should take care of the connection closing
     */
    private boolean workflowExecutorShouldClose = true;

    private Config() {
        supportedSignatureAndHashAlgorithms = new LinkedList<>();
        supportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA512));
        supportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA384));
        supportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA256));
        supportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA224));
        supportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA1));
        supportedSignatureAndHashAlgorithms
                .add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.MD5));
        supportedCompressionMethods = new LinkedList<>();
        supportedCompressionMethods.add(CompressionMethod.NULL);
        supportedCiphersuites = new LinkedList<>();
        supportedCiphersuites.addAll(CipherSuite.getImplemented());
        namedCurves = new LinkedList<>();
        namedCurves.add(NamedCurve.SECP192R1);
        namedCurves.add(NamedCurve.SECP256R1);
        namedCurves.add(NamedCurve.SECP384R1);
        namedCurves.add(NamedCurve.SECP521R1);
        pointFormats = new LinkedList<>();
        pointFormats.add(ECPointFormat.UNCOMPRESSED);
        try {
            ClassLoader loader = Config.class.getClassLoader();
            InputStream stream = loader.getResourceAsStream("default.jks");
            setKeyStore(KeystoreHandler.loadKeyStore(stream, "password"));
            setPrivateKey((PrivateKey) keyStore.getKey(alias, password.toCharArray()));
            setOurCertificate(JKSLoader.loadTLSCertificate(keyStore, alias));
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            throw new ConfigurationException("Could not load deauflt JKS!");
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(Config.class.getName()).log(Level.SEVERE, null, ex);
        }
        clientCertificateTypes = new LinkedList<>();
        clientCertificateTypes.add(ClientCertificateType.RSA_SIGN);
    }

    public boolean isWorkflowExecutorShouldOpen() {
        return workflowExecutorShouldOpen;
    }

    public void setWorkflowExecutorShouldOpen(boolean workflowExecutorShouldOpen) {
        this.workflowExecutorShouldOpen = workflowExecutorShouldOpen;
    }

    public boolean isWorkflowExecutorShouldClose() {
        return workflowExecutorShouldClose;
    }

    public void setWorkflowExecutorShouldClose(boolean workflowExecutorShouldClose) {
        this.workflowExecutorShouldClose = workflowExecutorShouldClose;
    }

    public boolean isQuickReceive() {
        return quickReceive;
    }

    public void setQuickReceive(boolean quickReceive) {
        this.quickReceive = quickReceive;
    }

    public boolean isStripWorkflowtracesBeforeSaving() {
        return stripWorkflowtracesBeforeSaving;
    }

    public void setStripWorkflowtracesBeforeSaving(boolean stripWorkflowtracesBeforeSaving) {
        this.stripWorkflowtracesBeforeSaving = stripWorkflowtracesBeforeSaving;
    }

    public RecordLayerType getRecordLayerType() {
        return recordLayerType;
    }

    public void setRecordLayerType(RecordLayerType recordLayerType) {
        this.recordLayerType = recordLayerType;
    }

    public boolean isFlushOnMessageTypeChange() {
        return flushOnMessageTypeChange;
    }

    public void setFlushOnMessageTypeChange(boolean flushOnMessageTypeChange) {
        this.flushOnMessageTypeChange = flushOnMessageTypeChange;
    }

    public boolean isCreateRecordsDynamically() {
        return createRecordsDynamically;
    }

    public void setCreateRecordsDynamically(boolean createRecordsDynamically) {
        this.createRecordsDynamically = createRecordsDynamically;
    }

    public boolean isCreateIndividualRecords() {
        return createIndividualRecords;
    }

    public void setCreateIndividualRecords(boolean createIndividualRecords) {
        this.createIndividualRecords = createIndividualRecords;
    }

    public int getDefaultMaxRecordData() {
        return defaultMaxRecordData;
    }

    public void setDefaultMaxRecordData(int defaultMaxRecordData) {
        this.defaultMaxRecordData = defaultMaxRecordData;
    }

    public ExecutorType getExecutorType() {
        return executorType;
    }

    public void setExecutorType(ExecutorType executorType) {
        this.executorType = executorType;
    }

    public NameType getSniType() {
        return sniType;
    }

    public void setSniType(NameType sniType) {
        this.sniType = sniType;
    }

    public int getHeartbeatPayloadLength() {
        return heartbeatPayloadLength;
    }

    public void setHeartbeatPayloadLength(int heartbeatPayloadLength) {
        this.heartbeatPayloadLength = heartbeatPayloadLength;
    }

    public int getHeartbeatMinPaddingLength() {
        return heartbeatMinPaddingLength;
    }

    public void setHeartbeatMinPaddingLength(int heartbeatMinPaddingLength) {
        this.heartbeatMinPaddingLength = heartbeatMinPaddingLength;
    }

    public int getHeartbeatMaxPaddingLength() {
        return heartbeatMaxPaddingLength;
    }

    public void setHeartbeatMaxPaddingLength(int heartbeatMaxPaddingLength) {
        this.heartbeatMaxPaddingLength = heartbeatMaxPaddingLength;
    }

    public boolean isAddPaddingExtension() {
        return addPaddingExtension;
    }

    public void setAddPaddingExtension(boolean addPaddingExtension) {
        this.addPaddingExtension = addPaddingExtension;
    }

    public boolean isAddExtendedMasterSecretExtension() {
        return addExtendedMasterSecretExtension;
    }

    public void setAddExtendedMasterSecretExtension(boolean addExtendedMasterSecretExtension) {
        this.addExtendedMasterSecretExtension = addExtendedMasterSecretExtension;
    }

    public boolean isAddSessionTicketTLSExtension() {
        return addSessionTicketTLSExtension;
    }

    public void setAddSessionTicketTLSExtension(boolean addSessionTicketTLSExtension) {
        this.addSessionTicketTLSExtension = addSessionTicketTLSExtension;
    }

    public byte[] getDefaultPaddingExtensionBytes() {
        return defaultPaddingExtensionBytes;
    }

    public void setDefaultPaddingExtensionBytes(byte[] defaultPaddingExtensionBytes) {
        this.defaultPaddingExtensionBytes = defaultPaddingExtensionBytes;
    }

    public List<ClientCertificateType> getClientCertificateTypes() {
        return clientCertificateTypes;
    }

    public void setClientCertificateTypes(List<ClientCertificateType> clientCertificateTypes) {
        this.clientCertificateTypes = clientCertificateTypes;
    }

    public boolean isWaitOnlyForExpectedDTLS() {
        return waitOnlyForExpectedDTLS;
    }

    public void setWaitOnlyForExpectedDTLS(boolean waitOnlyForExpectedDTLS) {
        this.waitOnlyForExpectedDTLS = waitOnlyForExpectedDTLS;
    }

    public String getDefaultApplicationMessageData() {
        return defaultApplicationMessageData;
    }

    public boolean isDoDTLSRetransmits() {
        return doDTLSRetransmits;
    }

    public void setDoDTLSRetransmits(boolean doDTLSRetransmits) {
        this.doDTLSRetransmits = doDTLSRetransmits;
    }

    public void setDefaultApplicationMessageData(String defaultApplicationMessageData) {
        this.defaultApplicationMessageData = defaultApplicationMessageData;
    }

    public boolean isEnforceSettings() {
        return enforceSettings;
    }

    public void setEnforceSettings(boolean enforceSettings) {
        this.enforceSettings = enforceSettings;
    }

    public byte[] getFixedDHg() {
        return fixedDHg;
    }

    public void setFixedDHg(byte[] fixedDHg) {
        this.fixedDHg = fixedDHg;
    }

    public byte[] getFixedDHModulus() {
        return fixedDHModulus;
    }

    public void setFixedDHModulus(byte[] fixedDHModulus) {
        this.fixedDHModulus = fixedDHModulus;
    }

    public byte[] getDistinguishedNames() {
        return distinguishedNames;
    }

    public void setDistinguishedNames(byte[] distinguishedNames) {
        this.distinguishedNames = distinguishedNames;
    }

    public Certificate getOurCertificate() {
        return ourCertificate;
    }

    public void setOurCertificate(Certificate ourCertificate) {
        this.ourCertificate = ourCertificate;
    }

    public ProtocolVersion getHighestProtocolVersion() {
        return highestProtocolVersion;
    }

    public void setHighestProtocolVersion(ProtocolVersion highestProtocolVersion) {
        this.highestProtocolVersion = highestProtocolVersion;
    }

    public boolean isUpdateTimestamps() {
        return updateTimestamps;
    }

    public void setUpdateTimestamps(boolean updateTimestamps) {
        this.updateTimestamps = updateTimestamps;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public boolean isServerSendsApplicationData() {
        return serverSendsApplicationData;
    }

    public void setServerSendsApplicationData(boolean serverSendsApplicationData) {
        this.serverSendsApplicationData = serverSendsApplicationData;
    }

    public WorkflowTraceType getWorkflowTraceType() {
        return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
        this.workflowTraceType = workflowTraceType;
    }

    public String getWorkflowOutput() {
        return workflowOutput;
    }

    public void setWorkflowOutput(String workflowOutput) {
        this.workflowOutput = workflowOutput;
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    public boolean isVerifyWorkflow() {
        return verifyWorkflow;
    }

    public void setVerifyWorkflow(boolean verifyWorkflow) {
        this.verifyWorkflow = verifyWorkflow;
    }

    public TransportHandlerType getTransportHandlerType() {
        return transportHandlerType;
    }

    public void setTransportHandlerType(TransportHandlerType transportHandlerType) {
        this.transportHandlerType = transportHandlerType;
    }

    public int getTlsTimeout() {
        return tlsTimeout;
    }

    public void setTlsTimeout(int tlsTimeout) {
        this.tlsTimeout = tlsTimeout;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isSniHostnameFatal() {
        return sniHostnameFatal;
    }

    public void setSniHostnameFatal(boolean sniHostnameFatal) {
        this.sniHostnameFatal = sniHostnameFatal;
    }

    public MaxFragmentLength getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(MaxFragmentLength maxFragmentLengthConfig) {
        this.maxFragmentLength = maxFragmentLengthConfig;
    }

    public String getSniHostname() {
        return sniHostname;
    }

    public void setSniHostname(String SniHostname) {
        this.sniHostname = SniHostname;
    }

    public boolean isDynamicWorkflow() {
        return dynamicWorkflow;
    }

    public void setDynamicWorkflow(boolean dynamicWorkflow) {
        this.dynamicWorkflow = dynamicWorkflow;
    }

    public List<CipherSuite> getSupportedCiphersuites() {
        return Collections.unmodifiableList(supportedCiphersuites);
    }

    public void setSupportedCiphersuites(List<CipherSuite> supportedCiphersuites) {
        this.supportedCiphersuites = supportedCiphersuites;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return Collections.unmodifiableList(supportedCompressionMethods);
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public ConnectionEndType getConnectionEndType() {
        return connectionEndType;
    }

    public void setConnectionEndType(ConnectionEndType connectionEndType) {
        this.connectionEndType = connectionEndType;
    }

    public ConnectionEndType getMyConnectionPeer() {
        return connectionEndType == ConnectionEndType.CLIENT ? ConnectionEndType.SERVER : ConnectionEndType.CLIENT;
    }

    public WorkflowTrace getWorkflowTrace() {
        return workflowTrace;
    }

    public void setWorkflowTrace(WorkflowTrace workflowTrace) {
        this.workflowTrace = workflowTrace;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public boolean isClientAuthentication() {
        return clientAuthentication;
    }

    public void setClientAuthentication(boolean clientAuthentication) {
        this.clientAuthentication = clientAuthentication;
    }

    public boolean isSessionResumption() {
        return sessionResumption;
    }

    public void setSessionResumption(boolean sessionResumption) {
        this.sessionResumption = sessionResumption;
    }

    public boolean isRenegotiation() {
        return renegotiation;
    }

    public void setRenegotiation(boolean renegotiation) {
        this.renegotiation = renegotiation;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return Collections.unmodifiableList(supportedSignatureAndHashAlgorithms);
    }

    public void setSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public boolean isFuzzingMode() {
        return fuzzingMode;
    }

    public void setFuzzingMode(boolean fuzzingMode) {
        this.fuzzingMode = fuzzingMode;
    }

    public List<ECPointFormat> getPointFormats() {
        return Collections.unmodifiableList(pointFormats);
    }

    public void setPointFormats(List<ECPointFormat> pointFormats) {
        this.pointFormats = pointFormats;
    }

    public List<NamedCurve> getNamedCurves() {
        return Collections.unmodifiableList(namedCurves);
    }

    public void setNamedCurves(List<NamedCurve> namedCurves) {
        this.namedCurves = namedCurves;
    }

    public HeartbeatMode getHeartbeatMode() {
        return heartbeatMode;
    }

    public void setHeartbeatMode(HeartbeatMode heartbeatMode) {
        this.heartbeatMode = heartbeatMode;
    }

    public boolean isAddECPointFormatExtension() {
        return addECPointFormatExtension;
    }

    public void setAddECPointFormatExtension(boolean addECPointFormatExtension) {
        this.addECPointFormatExtension = addECPointFormatExtension;
    }

    public boolean isAddEllipticCurveExtension() {
        return addEllipticCurveExtension;
    }

    public void setAddEllipticCurveExtension(boolean addEllipticCurveExtension) {
        this.addEllipticCurveExtension = addEllipticCurveExtension;
    }

    public boolean isAddHeartbeatExtension() {
        return addHeartbeatExtension;
    }

    public void setAddHeartbeatExtension(boolean addHeartbeatExtension) {
        this.addHeartbeatExtension = addHeartbeatExtension;
    }

    public boolean isAddMaxFragmentLengthExtenstion() {
        return addMaxFragmentLengthExtenstion;
    }

    public void setAddMaxFragmentLengthExtenstion(boolean addMaxFragmentLengthExtenstion) {
        this.addMaxFragmentLengthExtenstion = addMaxFragmentLengthExtenstion;
    }

    public boolean isAddServerNameIndicationExtension() {
        return addServerNameIndicationExtension;
    }

    public void setAddServerNameIndicationExtension(boolean addServerNameIndicationExtension) {
        this.addServerNameIndicationExtension = addServerNameIndicationExtension;
    }

    public boolean isAddSignatureAndHashAlgrorithmsExtension() {
        return addSignatureAndHashAlgrorithmsExtension;
    }

    public void setAddSignatureAndHashAlgrorithmsExtension(boolean addSignatureAndHashAlgrorithmsExtension) {
        this.addSignatureAndHashAlgrorithmsExtension = addSignatureAndHashAlgrorithmsExtension;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public int getDefaultDTLSCookieLength() {
        return defaultDTLSCookieLength;
    }

    public void setDefaultDTLSCookieLength(int defaultDTLSCookieLength) {
        this.defaultDTLSCookieLength = defaultDTLSCookieLength;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(String keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public byte[] getTLSSessionTicket() {
        return TLSSessionTicket;
    }

    public void setTLSSessionTicket(byte[] TLSSessionTicket) {
        this.TLSSessionTicket = TLSSessionTicket;
    }

    public byte[] getSignedCertificateTimestamp() {
        return signedCertificateTimestamp;
    }

    public void setSignedCertificateTimestamp(byte[] signedCertificateTimestamp) {
        this.signedCertificateTimestamp = signedCertificateTimestamp;
    }

    public boolean isAddSignedCertificateTimestampExtension() {
        return addSignedCertificateTimestampExtension;
    }

    public void setAddSignedCertificateTimestampExtension(boolean addSignedCertificateTimestampExtension) {
        this.addSignedCertificateTimestampExtension = addSignedCertificateTimestampExtension;
    }

    public byte[] getRenegotiationInfo() {
        return renegotiationInfo;
    }

    public void setRenegotiationInfo(byte[] renegotiationInfo) {
        this.renegotiationInfo = renegotiationInfo;
    }

    public boolean isAddRenegotiationInfoExtension() {
        return addRenegotiationInfoExtension;
    }

    public void setAddRenegotiationInfoExtension(boolean addRenegotiationInfoExtension) {
        this.addRenegotiationInfoExtension = addRenegotiationInfoExtension;
    }

    public TokenBindingVersion getTokenBindingVersion() {
        return tokenBindingVersion;
    }

    public void setTokenBindingVersion(TokenBindingVersion tokenBindingVersion) {
        this.tokenBindingVersion = tokenBindingVersion;
    }

    public TokenBindingKeyParameters[] getTokenBindingKeyParameters() {
        return tokenBindingKeyParameters;
    }

    public void setTokenBindingKeyParameters(TokenBindingKeyParameters[] tokenBindingKeyParameters) {
        this.tokenBindingKeyParameters = tokenBindingKeyParameters;
    }

    public boolean isAddTokenBindingExtension() {
        return addTokenBindingExtension;
    }

    public void setAddTokenBindingExtension(boolean addTokenBindingExtension) {
        this.addTokenBindingExtension = addTokenBindingExtension;
    }

    public PublicKey getPublicKey() throws CertificateParsingException {
        X509CertificateObject certObj = new X509CertificateObject(getOurCertificate().getCertificateAt(0));
        return certObj.getPublicKey();

    }
}
