/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.SNIEntry;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
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

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
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
     * Supported ProtocolVersions by default
     */
    private List<ProtocolVersion> supportedVersions;
    /**
     * Which heartBeat mode we are in
     */
    private HeartbeatMode heartbeatMode = HeartbeatMode.PEER_ALLOWED_TO_SEND;
    /**
     * Padding length for TLS 1.3 messages
     */
    private int paddingLength = 0;
    /**
     * Public key for KeyShareExtension
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] keySharePublic = ArrayConverter
            .hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c");
    /**
     * Key type for KeyShareExtension
     */
    private NamedCurve keyShareType = NamedCurve.ECDH_X25519;
    /**
     * Private key for KeyShareExtension
     */
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] keySharePrivate = ArrayConverter
            .hexStringToByteArray("03bd8bca70c19f657e897e366dbe21a466e4924af6082dbdf573827bcdde5def");
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
     * If we generate ClientHello with the SupportedVersion extension
     */
    private boolean addSupportedVersionsExtension = false;
    /**
     * If we generate ClientHello with the KeyShare extension
     */
    private boolean addKeyShareExtension = false;
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
    private byte[] defaultRsaCertificate = ArrayConverter
            .hexStringToByteArray("0003970003943082039030820278A003020102020900A650C00794049FCD300D06092A864886F70D01010B0500305C310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B65723020170D3137303731333132353331385A180F32313137303631393132353331385A305C310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B657230820122300D06092A864886F70D01010105000382010F003082010A0282010100C8820D6C3CE84C8430F6835ABFC7D7A912E1664F44578751F376501A8C68476C3072D919C5D39BD0DBE080E71DB83BD4AB2F2F9BDE3DFFB0080F510A5F6929C196551F2B3C369BE051054C877573195558FD282035934DC86EDAB8D4B1B7F555E5B2FEE7275384A756EF86CB86793B5D1333F0973203CB96966766E655CD2CCCAE1940E4494B8E9FB5279593B75AFD0B378243E51A88F6EB88DEF522A8CD5C6C082286A04269A2879760FCBA45005D7F2672DD228809D47274F0FE0EA5531C2BD95366C05BF69EDC0F3C3189866EDCA0C57ADCCA93250AE78D9EACA0393A95FF9952FC47FB7679DD3803E6A7A6FA771861E3D99E4B551A4084668B111B7EEF7D0203010001A3533051301D0603551D0E04160414E7A92FE5543AEE2FF7592F800AC6E66541E3268B301F0603551D23041830168014E7A92FE5543AEE2FF7592F800AC6E66541E3268B300F0603551D130101FF040530030101FF300D06092A864886F70D01010B050003820101000D5C11E28CF19D1BC17E4FF543695168570AA7DB85B3ECB85405392A0EDAFE4F097EE4685B7285E3D9B869D23257161CA65E20B5E6A585D33DA5CD653AF81243318132C9F64A476EC08BA80486B3E439F765635A7EA8A969B3ABD8650036D74C5FC4A04589E9AC8DC3BE2708743A6CFE3B451E3740F735F156D6DC7FFC8A2C852CD4E397B942461C2FCA884C7AFB7EBEF7918D6AAEF1F0D257E959754C4665779FA0E3253EF2BEDBBD5BE5DA600A0A68E51D2D1C125C4E198669A6BC715E8F3884E9C3EFF39D40838ADA4B1F38313F6286AA395DC6DEA9DAF49396CF12EC47EFA7A0D3882F8B84D9AEEFFB252C6B81A566609605FBFD3F0D17E5B12401492A1A");

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultDsaCertificate = ArrayConverter
            .hexStringToByteArray("0003540003513082034D3082030AA0030201020209008371F01046D40E48300B0609608648016503040302305C310B30090603550406130244453113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B65723020170D3137303731333132303831375A180F32313137303631393132303831375A305C310B30090603550406130244453113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B6572308201B63082012B06072A8648CE3804013082011E02818100A6B0EAF2CCE3B4370D66CD94AA68E425DF90B68936924D7A2B19173D5FDDC3A9E569E914CB5C028E6DD31DE7127CE1452708E78A8883FA86659F0E4773DDCB6D529206CAB19C1F66FB9D3A11E336A8AA28A24B2D64B0E5096E5860C2D5F889958133A149A8256ADC7A2EF7F61F545B04352834C0EE455D256AA6FB888CB87FD5021500FF03353AB857DDA61F2823EE734253E8D4D35C3D028180170B66A05C3644899197FE9E3FF26116B907B3E8E90FA3CFE64D2E7EB43D219CEE46EF342E0C03461176FAF144D609B95201FEEF462027B932815375B511ABF8E0048886D9E20FADC5D8EF9AB5CAEFCB3FF667CA953A53F82E0FF301D923CAC922EE3735B231D40177EC9AD827998018C9039BE63B067E9AF06C9B7D5011CA82038184000281804A3726DCC3299945FCF932C12701101C948926560F3E33B8C6708908B5A88C0BDDDBA2F24EC672BA61F6F49680FB900F99F01C3A08E00D48F85FC239CF14F6EEE3FDB0DB6C88BC89B98FC122793AF8F1D9265870C00EEF42D1EE1ACB5FB3874A6CAFF4E44F822E2EB365461C0AF384B9925FFB561453C5BE5554C86F20CEC0DCA3533051301D0603551D0E041604149B1C1B884AE8690571A0FABC67B445E77779EC0D301F0603551D230418301680149B1C1B884AE8690571A0FABC67B445E77779EC0D300F0603551D130101FF040530030101FF300B0609608648016503040302033000302D021412B619CE0DCCAEF09F8BB0ACBFD146300C0C1B00021500BDE6CB6CF90058B533D050542E24BA1F64860226");

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultEcCertificate = ArrayConverter
            .hexStringToByteArray("0001BD0001BA308201B63082016CA003020102020900B9FB5B9B7B19C211300A06082A8648CE3D0403023045310B30090603550406130244453113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643020170D3137303731333132353530375A180F32313137303631393132353530375A3045310B30090603550406130244453113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643049301306072A8648CE3D020106082A8648CE3D03010103320004DF647234F375CB38137C6775B04A40950C932E180620717F802B21FE868479987D990383D908E19B683F412ECDF397E1A3533051301D0603551D0E04160414ACF90511E691018C1B69177AF743321486EE09D5301F0603551D23041830168014ACF90511E691018C1B69177AF743321486EE09D5300F0603551D130101FF040530030101FF300A06082A8648CE3D04030203380030350219009E8F2E5C4D6C4179B60E12B46B7AD19F7AF39F11731A359702180CDC387E4A12F6BBEE702A05B548C5F5FC2DE3842B6366A0");

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] distinguishedNames = new byte[0];

    private boolean enforceSettings = false;

    /**
     * Stop as soon as all configured messages are received and dont wait for
     * more
     */
    private boolean earlyStop = false;

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
     * If the WorkflowExecutor should take care of the connection opening
     */
    private boolean workflowExecutorShouldOpen = true;

    /**
     * If the WorkflowExecutor should take care of the connection closing
     */
    private boolean workflowExecutorShouldClose = true;

    private boolean stopRecievingAfterFatal = false;
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

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] defaultCertificateRequestContext = new byte[0];

    private PRFAlgorithm defaultPRFAlgorithm = PRFAlgorithm.TLS_PRF_LEGACY;

    private byte defaultAlertDescription = 0;

    private byte defaultAlertLevel = 0;

    private NamedCurve defaultSelectedCurve = NamedCurve.SECP192R1;

    private CustomECPoint defaultClientEcPublicKey;

    private CustomECPoint defaultServerEcPublicKey;

    private BigInteger defaultServerEcPrivateKey = new BigInteger(
            "191991257030464195512760799659436374116556484140110877679395918219072292938297573720808302564562486757422301181089761");

    private BigInteger defaultClientEcPrivateKey = new BigInteger(
            "191991257030464195512760799659436374116556484140110877679395918219072292938297573720808302564562486757422301181089761");

    private BigInteger defaultRSAModulus = new BigInteger(
            1,
            ArrayConverter
                    .hexStringToByteArray("00c8820d6c3ce84c8430f6835abfc7d7a912e1664f44578751f376501a8c68476c3072d919c5d39bd0dbe080e71db83bd4ab2f2f9bde3dffb0080f510a5f6929c196551f2b3c369be051054c877573195558fd282035934dc86edab8d4b1b7f555e5b2fee7275384a756ef86cb86793b5d1333f0973203cb96966766e655cd2cccae1940e4494b8e9fb5279593b75afd0b378243e51a88f6eb88def522a8cd5c6c082286a04269a2879760fcba45005d7f2672dd228809d47274f0fe0ea5531c2bd95366c05bf69edc0f3c3189866edca0c57adcca93250ae78d9eaca0393a95ff9952fc47fb7679dd3803e6a7a6fa771861e3d99e4b551a4084668b111b7eef7d"));// TODO

    private BigInteger defaultServerRSAPublicKey = new BigInteger("65537");

    private BigInteger defaultClientRSAPublicKey = new BigInteger("65537");

    private BigInteger defaultServerRSAPrivateKey = new BigInteger(
            1,
            ArrayConverter
                    .hexStringToByteArray("7dc0cb485a3edb56811aeab12cdcda8e48b023298dd453a37b4d75d9e0bbba27c98f0e4852c16fd52341ffb673f64b580b7111abf14bf323e53a2dfa92727364ddb34f541f74a478a077f15277c013606aea839307e6f5fec23fdd72506feea7cbe362697949b145fe8945823a39a898ac6583fc5fbaefa1e77cbc95b3b475e66106e92b906bdbb214b87bcc94020f317fc1c056c834e9cee0ad21951fbdca088274c4ef9d8c2004c6294f49b370fb249c1e2431fb80ce5d3dc9e342914501ef4c162e54e1ee4fed9369b82afc00821a29f4979a647e60935420d44184d98f9cb75122fb604642c6d1ff2b3a51dc32eefdc57d9a9407ad6a06d10e83e2965481"));// TODO

    private BigInteger defaultClientRSAPrivateKey = new BigInteger(
            1,
            ArrayConverter
                    .hexStringToByteArray("7dc0cb485a3edb56811aeab12cdcda8e48b023298dd453a37b4d75d9e0bbba27c98f0e4852c16fd52341ffb673f64b580b7111abf14bf323e53a2dfa92727364ddb34f541f74a478a077f15277c013606aea839307e6f5fec23fdd72506feea7cbe362697949b145fe8945823a39a898ac6583fc5fbaefa1e77cbc95b3b475e66106e92b906bdbb214b87bcc94020f317fc1c056c834e9cee0ad21951fbdca088274c4ef9d8c2004c6294f49b370fb249c1e2431fb80ce5d3dc9e342914501ef4c162e54e1ee4fed9369b82afc00821a29f4979a647e60935420d44184d98f9cb75122fb604642c6d1ff2b3a51dc32eefdc57d9a9407ad6a06d10e83e2965481"));// TODO

    private byte[] defaultClientHandshakeTrafficSecret = new byte[0];

    private byte[] defaultServerHandshakeTrafficSecret = new byte[0];

    private TokenBindingType defaultTokenBindingType = TokenBindingType.PROVIDED_TOKEN_BINDING;

    private CustomECPoint defaultTokenBindingECPublicKey = null;

    private BigInteger defaultTokenBindingRsaPublicKey = new BigInteger("65537");

    private BigInteger defaultTokenBindingRsaPrivateKey = new BigInteger(
            "89489425009274444368228545921773093919669586065884257445497854456487674839629818390934941973262879616797970608917283679875499331574161113854088813275488110588247193077582527278437906504015680623423550067240042466665654232383502922215493623289472138866445818789127946123407807725702626644091036502372545139713");

    private BigInteger defaultTokenBindingEcPrivateKey = new BigInteger("3");

    private BigInteger defaultTokenBindingRsaModulus = new BigInteger(
            "145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053");

    private ChooserType chooserType = ChooserType.DEFAULT;

    private KSEntry defaultServerKSEntry;

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
        defaultClientSupportedCiphersuites = new LinkedList<>();
        defaultClientSupportedCiphersuites.addAll(CipherSuite.getImplemented());
        defaultServerSupportedCiphersuites = new LinkedList<>();
        defaultServerSupportedCiphersuites.addAll(CipherSuite.getImplemented());
        namedCurves = new LinkedList<>();
        namedCurves.add(NamedCurve.SECP192R1);
        namedCurves.add(NamedCurve.SECP256R1);
        namedCurves.add(NamedCurve.SECP384R1);
        namedCurves.add(NamedCurve.SECP521R1);
        clientCertificateTypes = new LinkedList<>();
        clientCertificateTypes.add(ClientCertificateType.RSA_SIGN);
        supportedVersions = new LinkedList<>();
        supportedVersions.add(ProtocolVersion.TLS13);
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
        defaultClientEcPublicKey = new CustomECPoint(new BigInteger(
                "5477564916791683905639217522063413790465252514105158300031"), new BigInteger(
                "3142682168214624565874993023364886040439474355932713162721"));
        defaultServerEcPublicKey = new CustomECPoint(new BigInteger(
                "5477564916791683905639217522063413790465252514105158300031"), new BigInteger(
                "3142682168214624565874993023364886040439474355932713162721"));
        defaultServerKSEntry = new KSEntry(NamedCurve.SECP192R1, keySharePublic);
    }

    public ChooserType getChooserType() {
        return chooserType;
    }

    public void setChooserType(ChooserType chooserType) {
        this.chooserType = chooserType;
    }

    public boolean isEarlyStop() {
        return earlyStop;
    }

    public void setEarlyStop(boolean earlyStop) {
        this.earlyStop = earlyStop;
    }

    public CustomECPoint getDefaultTokenBindingECPublicKey() {
        return defaultTokenBindingECPublicKey;
    }

    public void setDefaultTokenBindingECPublicKey(CustomECPoint defaultTokenBindingECPublicKey) {
        this.defaultTokenBindingECPublicKey = defaultTokenBindingECPublicKey;
    }

    public BigInteger getDefaultTokenBindingRsaPublicKey() {
        return defaultTokenBindingRsaPublicKey;
    }

    public void setDefaultTokenBindingRsaPublicKey(BigInteger defaultTokenBindingRsaPublicKey) {
        this.defaultTokenBindingRsaPublicKey = defaultTokenBindingRsaPublicKey;
    }

    public BigInteger getDefaultTokenBindingRsaPrivateKey() {
        return defaultTokenBindingRsaPrivateKey;
    }

    public void setDefaultTokenBindingRsaPrivateKey(BigInteger defaultTokenBindingRsaPrivateKey) {
        this.defaultTokenBindingRsaPrivateKey = defaultTokenBindingRsaPrivateKey;
    }

    public BigInteger getDefaultTokenBindingEcPrivateKey() {
        return defaultTokenBindingEcPrivateKey;
    }

    public void setDefaultTokenBindingEcPrivateKey(BigInteger defaultTokenBindingEcPrivateKey) {
        this.defaultTokenBindingEcPrivateKey = defaultTokenBindingEcPrivateKey;
    }

    public BigInteger getDefaultTokenBindingRsaModulus() {
        return defaultTokenBindingRsaModulus;
    }

    public void setDefaultTokenBindingRsaModulus(BigInteger defaultTokenBindingRsaModulus) {
        this.defaultTokenBindingRsaModulus = defaultTokenBindingRsaModulus;
    }

    public TokenBindingType getDefaultTokenBindingType() {
        return defaultTokenBindingType;
    }

    public void setDefaultTokenBindingType(TokenBindingType defaultTokenBindingType) {
        this.defaultTokenBindingType = defaultTokenBindingType;
    }

    public byte[] getDefaultRsaCertificate() {
        return defaultRsaCertificate;
    }

    public void setDefaultRsaCertificate(byte[] defaultRsaCertificate) {
        this.defaultRsaCertificate = defaultRsaCertificate;
    }

    public byte[] getDefaultDsaCertificate() {
        return defaultDsaCertificate;
    }

    public void setDefaultDsaCertificate(byte[] defaultDsaCertificate) {
        this.defaultDsaCertificate = defaultDsaCertificate;
    }

    public byte[] getDefaultEcCertificate() {
        return defaultEcCertificate;
    }

    public void setDefaultEcCertificate(byte[] defaultEcCertificate) {
        this.defaultEcCertificate = defaultEcCertificate;
    }

    public byte[] getDefaultClientHandshakeTrafficSecret() {
        return defaultClientHandshakeTrafficSecret;
    }

    public void setDefaultClientHandshakeTrafficSecret(byte[] defaultClientHandshakeTrafficSecret) {
        this.defaultClientHandshakeTrafficSecret = defaultClientHandshakeTrafficSecret;
    }

    public byte[] getDefaultServerHandshakeTrafficSecret() {
        return defaultServerHandshakeTrafficSecret;
    }

    public void setDefaultServerHandshakeTrafficSecret(byte[] defaultServerHandshakeTrafficSecret) {
        this.defaultServerHandshakeTrafficSecret = defaultServerHandshakeTrafficSecret;
    }

    public byte[] getKeySharePublic() {
        return keySharePublic;
    }

    public void setKeySharePublic(byte[] keySharePublic) {
        this.keySharePublic = keySharePublic;
    }

    public byte[] getDefaultCertificateRequestContext() {
        return defaultCertificateRequestContext;
    }

    public void setDefaultCertificateRequestContext(byte[] defaultCertificateRequestContext) {
        this.defaultCertificateRequestContext = defaultCertificateRequestContext;
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

    public boolean isStopRecievingAfterFatal() {
        return stopRecievingAfterFatal;
    }

    public void setStopRecievingAfterFatal(boolean stopRecievingAfterFatal) {
        this.stopRecievingAfterFatal = stopRecievingAfterFatal;
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

    public NamedCurve getKeyShareType() {
        return keyShareType;
    }

    public void setKeyShareType(NamedCurve keyShareType) {
        this.keyShareType = keyShareType;
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

    public List<NamedCurve> getNamedCurves() {
        return Collections.unmodifiableList(namedCurves);
    }

    public void setNamedCurves(List<NamedCurve> namedCurves) {
        this.namedCurves = namedCurves;
    }

    public List<ProtocolVersion> getSupportedVersions() {
        return Collections.unmodifiableList(supportedVersions);
    }

    public void setSupportedVersions(List<ProtocolVersion> supportedVersions) {
        this.supportedVersions = supportedVersions;
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

    public boolean isAddSupportedVersionsExtension() {
        return addSupportedVersionsExtension;
    }

    public void setAddSupportedVersionsExtension(boolean addSupportedVersionsExtension) {
        this.addSupportedVersionsExtension = addSupportedVersionsExtension;
    }

    public boolean isAddKeyShareExtension() {
        return addKeyShareExtension;
    }

    public void setAddKeyShareExtension(boolean addKeyShareExtension) {
        this.addKeyShareExtension = addKeyShareExtension;
    }

    public int getDefaultDTLSCookieLength() {
        return defaultDTLSCookieLength;
    }

    public void setDefaultDTLSCookieLength(int defaultDTLSCookieLength) {
        this.defaultDTLSCookieLength = defaultDTLSCookieLength;
    }

    public int getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(int paddingLength) {
        this.paddingLength = paddingLength;
    }

    public byte[] getKeySharePrivate() {
        return keySharePrivate;
    }

    public void setKeySharePrivate(byte[] keySharePrivate) {
        this.keySharePrivate = keySharePrivate;
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

    public void setDefaultServerKSEntry(KSEntry defaultServerKSEntry) {
        this.defaultServerKSEntry = defaultServerKSEntry;
    }

    public KSEntry getDefaultServerKSEntry() {
        return defaultServerKSEntry;
    }
}
