/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
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
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.SNIEntry;
import de.rub.nds.tlsattacker.core.util.JKSLoader;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
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
public final class TlsConfig implements Serializable {

    /**
     * Default value for ProtocolVerionFields
     */
    private ProtocolVersion highestProtocolVersion = ProtocolVersion.TLS12;

    /**
     * Indicates which ConnectionEnd we are
     */
    private ConnectionEnd connectionEnd = ConnectionEnd.CLIENT;

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
    private List<CipherSuite> defaultClientSupportedCiphersuites;
    /**
     * Which Ciphersuites we support by default
     */
    private List<CipherSuite> defaultServerSupportedCiphersuites;
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
     * Default clientSupportedNamed Curves
     */
    private List<NamedCurve> defaultClientNamedCurves;
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
    private int serverPort = 4433;
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
    private byte[] defaultRenegotiationInfo = new byte[0];
    /**
     * SignedCertificateTimestamp for the SignedCertificateTimestampExtension.
     * It's an emty timestamp, since the server sends it.
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultSignedCertificateTimestamp = new byte[0];
    /**
     * TokenBinding default version. To be defined later.
     */
    private TokenBindingVersion defaultTokenBindingVersion = TokenBindingVersion.DRAFT_13;
    /**
     * Default TokenBinding Key Parameters.
     */
    private List<TokenBindingKeyParameters> defaultTokenBindingKeyParameters;
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
    private String workflowInput = null;
    /**
     * If we should output an executed workflowtrace to a specified file
     */
    private String workflowOutput = null;
    /**
     * The Type of workflow trace that should be generated
     */
    private WorkflowTraceType workflowTraceType = null;
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

    private BigInteger defaultDhGenerator = new BigInteger("2");

    private BigInteger defaultDhModulus = new BigInteger(
            "15458150092069033378601573800816703249401189342134115050806105600042321586262936062413786779796157671421516779431947968642017250021834283152850968840396649272235097918348324");

    private BigInteger defaultServerDhPrivateKey = new BigInteger(
            "1234567891234567889123546712839632542648746452354265471");

    private BigInteger defaultClientDhPrivateKey = new BigInteger(
            "1234567891234567889123546712839632542648746452354265471");

    private BigInteger defaultServerDhPublicKey = new BigInteger(
            "14480301636124364131011109953533209419584138262785800536726427889263750026424833537662211230987987661789535497502943331312908532241011314347509704298395798883527739408059572");

    private BigInteger defaultClientDhPublicKey = new BigInteger(
            "14480301636124364131011109953533209419584138262785800536726427889263750026424833537662211230987987661789535497502943331312908532241011314347509704298395798883527739408059572");

    private String defaultApplicationMessageData = "Test";

    @XmlTransient
    private PrivateKey privateKey = null;

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
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
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
     * This CipherSuite will be used if no cipherSuite has been negotiated yet
     */
    private CipherSuite defaultSelectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

    private List<ECPointFormat> defaultServerSupportedPointFormats;

    private List<ECPointFormat> defaultClientSupportedPointFormats;

    private List<SignatureAndHashAlgorithm> defaultClientSupportedSignatureAndHashAlgorithms;

    private List<SignatureAndHashAlgorithm> defaultServerSupportedSignatureAndHashAlgorithms;

    private SignatureAndHashAlgorithm defaultSelectedSignatureAndHashAlgorithm = new SignatureAndHashAlgorithm(
            SignatureAlgorithm.RSA, HashAlgorithm.SHA1);

    private List<SNIEntry> defaultClientSNIEntryList;

    private ProtocolVersion defaultLastRecordProtocolVersion = ProtocolVersion.TLS10;

    private ProtocolVersion defaultSelectedProtocolVersion = ProtocolVersion.TLS12;

    private ProtocolVersion defaultHighestClientProtocolVersion = ProtocolVersion.TLS12;

    private MaxFragmentLength defaultMaxFragmentLength = MaxFragmentLength.TWO_12;

    private HeartbeatMode defaultHeartbeatMode = HeartbeatMode.PEER_ALLOWED_TO_SEND;

    private List<CompressionMethod> defaultClientSupportedCompressionMethods;

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultMasterSecret = new byte[0];

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultPreMasterSecret = new byte[0];

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultClientRandom = new byte[0];

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultServerRandom = new byte[0];

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultClientSessionId = new byte[0];

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultServerSessionId = new byte[0];

    private CompressionMethod defaultSelectedCompressionMethod = CompressionMethod.NULL;

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultDtlsCookie = new byte[0];

    private PRFAlgorithm defaultPRFAlgorithm = PRFAlgorithm.TLS_PRF_LEGACY;

    public static TlsConfig createConfig() {
        InputStream stream = TlsConfig.class.getResourceAsStream("/default_config.xml");
        return TlsConfigIO.read(stream);
    }

    public static TlsConfig createConfig(File f) {
        return TlsConfigIO.read(f);
    }

    public static TlsConfig createConfig(InputStream stream) {
        TlsConfig config = TlsConfigIO.read(stream);
        return config;
    }

    private TlsConfig() {
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
        defaultClientSupportedCiphersuites = new LinkedList<>();
        defaultClientSupportedCiphersuites.addAll(CipherSuite.getImplemented());
        namedCurves = new LinkedList<>();
        namedCurves.add(NamedCurve.SECP192R1);
        namedCurves.add(NamedCurve.SECP256R1);
        namedCurves.add(NamedCurve.SECP384R1);
        namedCurves.add(NamedCurve.SECP521R1);
        pointFormats = new LinkedList<>();
        pointFormats.add(ECPointFormat.UNCOMPRESSED);
        try {
            ClassLoader loader = TlsConfig.class.getClassLoader();
            InputStream stream = loader.getResourceAsStream("default.jks");
            setKeyStore(KeystoreHandler.loadKeyStore(stream, "password"));
            setPrivateKey((PrivateKey) keyStore.getKey(alias, password.toCharArray()));
            setOurCertificate(JKSLoader.loadTLSCertificate(keyStore, alias));
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            throw new ConfigurationException("Could not load deauflt JKS!");
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(TlsConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        clientCertificateTypes = new LinkedList<>();
        clientCertificateTypes.add(ClientCertificateType.RSA_SIGN);
        defaultTokenBindingKeyParameters = new LinkedList<>();
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.ECDSAP256);
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.RSA2048_PKCS1_5);
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.RSA2048_PSS);
        defaultServerSupportedSignatureAndHashAlgorithms = new LinkedList<>();
        defaultServerSupportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA1));
    }

    public BigInteger getDefaultServerDhPublicKey() {
        return defaultServerDhPublicKey;
    }

    public void setDefaultServerDhPublicKey(BigInteger defaultServerDhPublicKey) {
        this.defaultServerDhPublicKey = defaultServerDhPublicKey;
    }

    public BigInteger getDefaultClientDhPublicKey() {
        return defaultClientDhPublicKey;
    }

    public void setDefaultClientDhPublicKey(BigInteger defaultClientDhPublicKey) {
        this.defaultClientDhPublicKey = defaultClientDhPublicKey;
    }

    public BigInteger getDefaultServerDhPrivateKey() {
        return defaultServerDhPrivateKey;
    }

    public void setDefaultServerDhPrivateKey(BigInteger defaultServerDhPrivateKey) {
        this.defaultServerDhPrivateKey = defaultServerDhPrivateKey;
    }

    public PRFAlgorithm getDefaultPRFAlgorithm() {
        return defaultPRFAlgorithm;
    }

    public void setDefaultPRFAlgorithm(PRFAlgorithm defaultPRFAlgorithm) {
        this.defaultPRFAlgorithm = defaultPRFAlgorithm;
    }

    public byte[] getDefaultDtlsCookie() {
        return defaultDtlsCookie;
    }

    public void setDefaultDtlsCookie(byte[] defaultDtlsCookie) {
        this.defaultDtlsCookie = defaultDtlsCookie;
    }

    public byte[] getDefaultClientSessionId() {
        return defaultClientSessionId;
    }

    public void setDefaultClientSessionId(byte[] defaultClientSessionId) {
        this.defaultClientSessionId = defaultClientSessionId;
    }

    public byte[] getDefaultServerSessionId() {
        return defaultServerSessionId;
    }

    public void setDefaultServerSessionId(byte[] defaultServerSessionId) {
        this.defaultServerSessionId = defaultServerSessionId;
    }

    public CompressionMethod getDefaultSelectedCompressionMethod() {
        return defaultSelectedCompressionMethod;
    }

    public void setDefaultSelectedCompressionMethod(CompressionMethod defaultSelectedCompressionMethod) {
        this.defaultSelectedCompressionMethod = defaultSelectedCompressionMethod;
    }

    public byte[] getDefaultServerRandom() {
        return defaultServerRandom;
    }

    public void setDefaultServerRandom(byte[] defaultServerRandom) {
        this.defaultServerRandom = defaultServerRandom;
    }

    public byte[] getDefaultClientRandom() {
        return defaultClientRandom;
    }

    public void setDefaultClientRandom(byte[] defaultClientRandom) {
        this.defaultClientRandom = defaultClientRandom;
    }

    public byte[] getDefaultPreMasterSecret() {
        return defaultPreMasterSecret;
    }

    public void setDefaultPreMasterSecret(byte[] defaultPreMasterSecret) {
        this.defaultPreMasterSecret = defaultPreMasterSecret;
    }

    public byte[] getDefaultMasterSecret() {
        return defaultMasterSecret;
    }

    public void setDefaultMasterSecret(byte[] defaultMasterSecret) {
        this.defaultMasterSecret = defaultMasterSecret;
    }

    public ProtocolVersion getDefaultHighestClientProtocolVersion() {
        return defaultHighestClientProtocolVersion;
    }

    public void setDefaultHighestClientProtocolVersion(ProtocolVersion defaultHighestClientProtocolVersion) {
        this.defaultHighestClientProtocolVersion = defaultHighestClientProtocolVersion;
    }

    public ProtocolVersion getDefaultSelectedProtocolVersion() {
        return defaultSelectedProtocolVersion;
    }

    public void setDefaultSelectedProtocolVersion(ProtocolVersion defaultSelectedProtocolVersion) {
        this.defaultSelectedProtocolVersion = defaultSelectedProtocolVersion;
    }

    public List<SignatureAndHashAlgorithm> getDefaultServerSupportedSignatureAndHashAlgorithms() {
        return defaultServerSupportedSignatureAndHashAlgorithms;
    }

    public void setDefaultServerSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> defaultServerSupportedSignatureAndHashAlgorithms) {
        this.defaultServerSupportedSignatureAndHashAlgorithms = defaultServerSupportedSignatureAndHashAlgorithms;
    }

    public List<CipherSuite> getDefaultServerSupportedCiphersuites() {
        return defaultServerSupportedCiphersuites;
    }

    public void setDefaultServerSupportedCiphersuites(List<CipherSuite> defaultServerSupportedCiphersuites) {
        this.defaultServerSupportedCiphersuites = defaultServerSupportedCiphersuites;
    }

    public List<CompressionMethod> getDefaultClientSupportedCompressionMethods() {
        return defaultClientSupportedCompressionMethods;
    }

    public void setDefaultClientSupportedCompressionMethods(
            List<CompressionMethod> defaultClientSupportedCompressionMethods) {
        this.defaultClientSupportedCompressionMethods = defaultClientSupportedCompressionMethods;
    }

    public HeartbeatMode getDefaultHeartbeatMode() {
        return defaultHeartbeatMode;
    }

    public void setDefaultHeartbeatMode(HeartbeatMode defaultHeartbeatMode) {
        this.defaultHeartbeatMode = defaultHeartbeatMode;
    }

    public MaxFragmentLength getDefaultMaxFragmentLength() {
        return defaultMaxFragmentLength;
    }

    public void setDefaultMaxFragmentLength(MaxFragmentLength defaultMaxFragmentLength) {
        this.defaultMaxFragmentLength = defaultMaxFragmentLength;
    }

    public SignatureAndHashAlgorithm getDefaultSelectedSignatureAndHashAlgorithm() {
        return defaultSelectedSignatureAndHashAlgorithm;
    }

    public void setDefaultSelectedSignatureAndHashAlgorithm(
            SignatureAndHashAlgorithm defaultSelectedSignatureAndHashAlgorithm) {
        this.defaultSelectedSignatureAndHashAlgorithm = defaultSelectedSignatureAndHashAlgorithm;
    }

    public List<ECPointFormat> getDefaultClientSupportedPointFormats() {
        return defaultClientSupportedPointFormats;
    }

    public void setDefaultClientSupportedPointFormats(List<ECPointFormat> defaultClientSupportedPointFormats) {
        this.defaultClientSupportedPointFormats = defaultClientSupportedPointFormats;
    }

    public ProtocolVersion getDefaultLastRecordProtocolVersion() {
        return defaultLastRecordProtocolVersion;
    }

    public void setDefaultLastRecordProtocolVersion(ProtocolVersion defaultLastRecordProtocolVersion) {
        this.defaultLastRecordProtocolVersion = defaultLastRecordProtocolVersion;
    }

    public List<SNIEntry> getDefaultClientSNIEntryList() {
        return defaultClientSNIEntryList;
    }

    public void setDefaultClientSNIEntryList(List<SNIEntry> defaultClientSNIEntryList) {
        this.defaultClientSNIEntryList = defaultClientSNIEntryList;
    }

    public List<SignatureAndHashAlgorithm> getDefaultClientSupportedSignatureAndHashAlgorithms() {
        return defaultClientSupportedSignatureAndHashAlgorithms;
    }

    public void setDefaultClientSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> defaultClientSupportedSignatureAndHashAlgorithms) {
        this.defaultClientSupportedSignatureAndHashAlgorithms = defaultClientSupportedSignatureAndHashAlgorithms;
    }

    public List<ECPointFormat> getDefaultServerSupportedPointFormats() {
        return defaultServerSupportedPointFormats;
    }

    public void setDefaultServerSupportedPointFormats(List<ECPointFormat> defaultServerSupportedPointFormats) {
        this.defaultServerSupportedPointFormats = defaultServerSupportedPointFormats;
    }

    public List<NamedCurve> getDefaultClientNamedCurves() {
        return defaultClientNamedCurves;
    }

    public void setDefaultClientNamedCurves(List<NamedCurve> defaultClientNamedCurves) {
        this.defaultClientNamedCurves = defaultClientNamedCurves;
    }

    public CipherSuite getDefaultSelectedCipherSuite() {
        return defaultSelectedCipherSuite;
    }

    public void setDefaultSelectedCipherSuite(CipherSuite defaultSelectedCipherSuite) {
        this.defaultSelectedCipherSuite = defaultSelectedCipherSuite;
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

    public BigInteger getDefaultDhGenerator() {
        return defaultDhGenerator;
    }

    public void setDefaultDhGenerator(BigInteger defaultDhGenerator) {
        this.defaultDhGenerator = defaultDhGenerator;
    }

    public BigInteger getDefaultDhModulus() {
        return defaultDhModulus;
    }

    public void setDefaultDhModulus(BigInteger defaultDhModulus) {
        this.defaultDhModulus = defaultDhModulus;
    }

    public BigInteger getDefaultClientDhPrivateKey() {
        return defaultClientDhPrivateKey;
    }

    public void setDefaultClientDhPrivateKey(BigInteger defaultClientDhPrivateKey) {
        this.defaultClientDhPrivateKey = defaultClientDhPrivateKey;
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

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
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

    public List<CipherSuite> getDefaultClientSupportedCiphersuites() {
        return Collections.unmodifiableList(defaultClientSupportedCiphersuites);
    }

    public void setDefaultClientSupportedCiphersuites(List<CipherSuite> defaultClientSupportedCiphersuites) {
        this.defaultClientSupportedCiphersuites = defaultClientSupportedCiphersuites;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return Collections.unmodifiableList(supportedCompressionMethods);
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public ConnectionEnd getConnectionEnd() {
        return connectionEnd;
    }

    public void setConnectionEnd(ConnectionEnd connectionEnd) {
        this.connectionEnd = connectionEnd;
    }

    public ConnectionEnd getMyConnectionPeer() {
        return connectionEnd == ConnectionEnd.CLIENT ? ConnectionEnd.SERVER : ConnectionEnd.CLIENT;
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

    public byte[] getDefaultSignedCertificateTimestamp() {
        return defaultSignedCertificateTimestamp;
    }

    public void setDefaultSignedCertificateTimestamp(byte[] defaultSignedCertificateTimestamp) {
        this.defaultSignedCertificateTimestamp = defaultSignedCertificateTimestamp;
    }

    public boolean isAddSignedCertificateTimestampExtension() {
        return addSignedCertificateTimestampExtension;
    }

    public void setAddSignedCertificateTimestampExtension(boolean addSignedCertificateTimestampExtension) {
        this.addSignedCertificateTimestampExtension = addSignedCertificateTimestampExtension;
    }

    public byte[] getDefaultRenegotiationInfo() {
        return defaultRenegotiationInfo;
    }

    public void setDefaultRenegotiationInfo(byte[] defaultRenegotiationInfo) {
        this.defaultRenegotiationInfo = defaultRenegotiationInfo;
    }

    public boolean isAddRenegotiationInfoExtension() {
        return addRenegotiationInfoExtension;
    }

    public void setAddRenegotiationInfoExtension(boolean addRenegotiationInfoExtension) {
        this.addRenegotiationInfoExtension = addRenegotiationInfoExtension;
    }

    public TokenBindingVersion getDefaultTokenBindingVersion() {
        return defaultTokenBindingVersion;
    }

    public void setDefaultTokenBindingVersion(TokenBindingVersion defaultTokenBindingVersion) {
        this.defaultTokenBindingVersion = defaultTokenBindingVersion;
    }

    public List<TokenBindingKeyParameters> getDefaultTokenBindingKeyParameters() {
        return defaultTokenBindingKeyParameters;
    }

    public void setDefaultTokenBindingKeyParameters(List<TokenBindingKeyParameters> defaultTokenBindingKeyParameters) {
        this.defaultTokenBindingKeyParameters = defaultTokenBindingKeyParameters;
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
