/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.SNIEntry;
import java.io.File;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.bouncycastle.math.ec.ECPoint;

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
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] ourCertificate = ArrayConverter
            .hexStringToByteArray("0003ee0003eb308203e7308202cfa003020102020900b9eed4d955a59eb3300d06092a864886f70d01010505003070310b300906035504061302554b31163014060355040a0c0d4f70656e53534c2047726f757031223020060355040b0c19464f522054455354494e4720505552504f534553204f4e4c593125302306035504030c1c4f70656e53534c205465737420496e7465726d656469617465204341301e170d3131313230383134303134385a170d3231313031363134303134385a3064310b300906035504061302554b31163014060355040a0c0d4f70656e53534c2047726f757031223020060355040b0c19464f522054455354494e4720505552504f534553204f4e4c593119301706035504030c105465737420536572766572204365727430820122300d06092a864886f70d01010105000382010f003082010a0282010100f384f39236dcb246ca667ae529c5f3492822d3b9fee0dee438ceee221ce9913b94d0722f8785594b66b1c5f57a855dc20fd32e295836cc486ba2a2b526ce67e247b6df49d23ffaa210b7c297447e87346d6df28bb4552bd621de534b90eafdeaf938352bf4e69a0ef6bb12ab8721c32fbcf406b88f8e10072795e542cbd1d5108c92acee0fdc234889c9c6930c2202e774e72500abf80f5c10b5853b6694f0fb4d570655212225dbf3aaa960bf4daa79d1ab9248ba198e12ec68d9c6badfec5a1cd843fee752c9cf02d0c77fc97eb094e35344580b2efd2974b5069b5c448dfb3275a43aa8677b87320a508de1a2134a25afe61cb125bfb499a253d3a202bf110203010001a3818f30818c300c0603551d130101ff04023000300e0603551d0f0101ff0404030205e0302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465301d0603551d0e0416041482bccf000013d1f739259a27e7afd2ef201b6eac301f0603551d2304183016801436c36c88e795feb0bdecce3e3d86ab218187dada300d06092a864886f70d01010505000382010100a9bd4d574074fe96e92bd678fdb363ccf40b4d12ca5a748d9bf261e6fd06114384fc17a0ec636336b99e366ab1025a6a5b3f6aa1ea0565ac7e401a486588d1394dd34b77e9c8bb2b9e5af408343947b90208319af1d917c5e9a6a5964b6d40a95b6528cbcb0003826337d3adb1963b76f51716027bbd5353467234d608649dbb43fb64b149077709617a421711300cd9275cf571b6f01830f37ef1853f327e4aafb310f76cc6854b2d27ad0a205cfb8d197034b9755f7c87d5c3ec931341fc7303b98d1afef726864903a9c5823f800d2949b18fed241bfecf589046e7a887d41e79ef996d189f3e8b8207c143c7e025b6f1d300d740ab4b7f2b7a3ea6994c54");

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

    private int heartbeatPaddingLength = 256;

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

    private byte defaultAlertDescription = 0;

    private byte defaultAlertLevel = 0;

    private NamedCurve defaultSelectedCurve = NamedCurve.SECP256R1;

    private CustomECPoint defaultClientEcPublicKey;

    private CustomECPoint defaultServerEcPublicKey;

    private BigInteger defaultServerEcPrivateKey = new BigInteger("3");

    private BigInteger defaultClientEcPrivateKey = new BigInteger("3");

    private BigInteger defaultRSAModulus = new BigInteger(
            "145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053");// TODO

    private BigInteger defaultServerRSAPublicKey = new BigInteger("65537");

    private BigInteger defaultClientRSAPublicKey = new BigInteger("65537");

    private BigInteger defaultServerRSAPrivateKey = new BigInteger(
            "89489425009274444368228545921773093919669586065884257445497854456487674839629818390934941973262879616797970608917283679875499331574161113854088813275488110588247193077582527278437906504015680623423550067240042466665654232383502922215493623289472138866445818789127946123407807725702626644091036502372545139713");

    private BigInteger defaultClientRSAPrivateKey = new BigInteger(
            "89489425009274444368228545921773093919669586065884257445497854456487674839629818390934941973262879616797970608917283679875499331574161113854088813275488110588247193077582527278437906504015680623423550067240042466665654232383502922215493623289472138866445818789127946123407807725702626644091036502372545139713");

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
        clientCertificateTypes = new LinkedList<>();
        clientCertificateTypes.add(ClientCertificateType.RSA_SIGN);
        defaultTokenBindingKeyParameters = new LinkedList<>();
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.ECDSAP256);
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.RSA2048_PKCS1_5);
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.RSA2048_PSS);
        defaultServerSupportedSignatureAndHashAlgorithms = new LinkedList<>();
        defaultServerSupportedSignatureAndHashAlgorithms.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA1));
        defaultServerSupportedPointFormats = new LinkedList<>();
        defaultClientSupportedPointFormats = new LinkedList<>();
        defaultServerSupportedPointFormats.add(ECPointFormat.UNCOMPRESSED);
        defaultClientSupportedPointFormats.add(ECPointFormat.UNCOMPRESSED);
        defaultClientEcPublicKey = new CustomECPoint(new BigInteger("3"), new BigInteger("3"));
        defaultClientEcPublicKey = new CustomECPoint(new BigInteger("3"), new BigInteger("3"));
    }

    public byte[] getOurCertificate() {
        return ourCertificate;
    }

    public void setOurCertificate(byte[] ourCertificate) {
        this.ourCertificate = ourCertificate;
    }

    public BigInteger getDefaultClientRSAPrivateKey() {
        return defaultClientRSAPrivateKey;
    }

    public void setDefaultClientRSAPrivateKey(BigInteger defaultClientRSAPrivateKey) {
        this.defaultClientRSAPrivateKey = defaultClientRSAPrivateKey;
    }

    public BigInteger getDefaultServerRSAPrivateKey() {
        return defaultServerRSAPrivateKey;
    }

    public void setDefaultServerRSAPrivateKey(BigInteger defaultServerRSAPrivateKey) {
        this.defaultServerRSAPrivateKey = defaultServerRSAPrivateKey;
    }

    public BigInteger getDefaultRSAModulus() {
        return defaultRSAModulus;
    }

    public void setDefaultRSAModulus(BigInteger defaultRSAModulus) {
        if (defaultRSAModulus.signum() == 1) {
            this.defaultRSAModulus = defaultRSAModulus;
        } else {
            throw new IllegalArgumentException("Modulus cannot be negative or zero" + defaultRSAModulus.toString());
        }
    }

    public BigInteger getDefaultServerRSAPublicKey() {
        return defaultServerRSAPublicKey;
    }

    public void setDefaultServerRSAPublicKey(BigInteger defaultServerRSAPublicKey) {
        this.defaultServerRSAPublicKey = defaultServerRSAPublicKey;
    }

    public BigInteger getDefaultClientRSAPublicKey() {
        return defaultClientRSAPublicKey;
    }

    public void setDefaultClientRSAPublicKey(BigInteger defaultClientRSAPublicKey) {
        this.defaultClientRSAPublicKey = defaultClientRSAPublicKey;
    }

    public BigInteger getDefaultServerEcPrivateKey() {
        return defaultServerEcPrivateKey;
    }

    public void setDefaultServerEcPrivateKey(BigInteger defaultServerEcPrivateKey) {
        this.defaultServerEcPrivateKey = defaultServerEcPrivateKey;
    }

    public BigInteger getDefaultClientEcPrivateKey() {
        return defaultClientEcPrivateKey;
    }

    public void setDefaultClientEcPrivateKey(BigInteger defaultClientEcPrivateKey) {
        this.defaultClientEcPrivateKey = defaultClientEcPrivateKey;
    }

    public NamedCurve getDefaultSelectedCurve() {
        return defaultSelectedCurve;
    }

    public void setDefaultSelectedCurve(NamedCurve defaultSelectedCurve) {
        this.defaultSelectedCurve = defaultSelectedCurve;
    }

    public CustomECPoint getDefaultClientEcPublicKey() {
        return defaultClientEcPublicKey;
    }

    public void setDefaultClientEcPublicKey(CustomECPoint defaultClientEcPublicKey) {
        this.defaultClientEcPublicKey = defaultClientEcPublicKey;
    }

    public CustomECPoint getDefaultServerEcPublicKey() {
        return defaultServerEcPublicKey;
    }

    public void setDefaultServerEcPublicKey(CustomECPoint defaultServerEcPublicKey) {
        this.defaultServerEcPublicKey = defaultServerEcPublicKey;
    }

    public byte getDefaultAlertDescription() {
        return defaultAlertDescription;
    }

    public void setDefaultAlertDescription(byte defaultAlertDescription) {
        this.defaultAlertDescription = defaultAlertDescription;
    }

    public byte getDefaultAlertLevel() {
        return defaultAlertLevel;
    }

    public void setDefaultAlertLevel(byte defaultAlertLevel) {
        this.defaultAlertLevel = defaultAlertLevel;
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

    public int getHeartbeatPaddingLength() {
        return heartbeatPaddingLength;
    }

    public void setHeartbeatPaddingLength(int heartbeatPaddingLength) {
        this.heartbeatPaddingLength = heartbeatPaddingLength;
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
        if (defaultDhModulus.signum() == 1) {
            this.defaultDhModulus = defaultDhModulus;
        } else {
            throw new IllegalArgumentException("Modulus cannot be negative or zero:" + defaultDhModulus.toString());
        }
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

    public int getDefaultDTLSCookieLength() {
        return defaultDTLSCookieLength;
    }

    public void setDefaultDTLSCookieLength(int defaultDTLSCookieLength) {
        this.defaultDTLSCookieLength = defaultDTLSCookieLength;
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
}
