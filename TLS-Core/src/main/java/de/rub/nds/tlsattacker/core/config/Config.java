/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config;

import static java.nio.charset.StandardCharsets.US_ASCII;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.protocol.constants.MacAlgorithm;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.tlsattacker.core.config.adapter.MapAdapter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterType;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.filesystem.CertificateBytes;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@SuppressWarnings("SpellCheckingInspection")
@XmlRootElement(name = "config")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(propOrder = {})
public class Config implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * @deprecated Just use the constructor instead
     */
    @Deprecated
    public static Config createConfig() {
        return new Config();
    }

    public static Config createConfig(File f) {
        return ConfigIO.read(f);
    }

    public static Config createConfig(InputStream stream) {
        return ConfigIO.read(stream);
    }

    public static Config createEmptyConfig() {
        Config c = new Config();
        for (Field field : c.getClass().getDeclaredFields()) {
            if (!field.getName().equals("LOGGER")
                    && !field.getType().isPrimitive()
                    && !field.getName().contains("Extension")) {
                field.setAccessible(true);
                try {
                    field.set(c, null);
                } catch (IllegalAccessException e) {
                    LOGGER.warn("Could not set field in Config!", e);
                }
            }
        }
        return c;
    }

    private Boolean respectPeerRecordSizeLimitations = true;

    private StackConfiguration defaultLayerConfiguration;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultHandshakeSecret = new byte[32];

    /**
     * If this is non-null, TLS-Attacker will not create its own certificate chain but will simply
     * send the bytes in the list as the certificates in the chain in the provided order
     */
    @XmlElement(name = "certificateBytes")
    @XmlElementWrapper
    private List<CertificateBytes> defaultExplicitCertificateChain = null;

    /**
     * If set to true, dynamically creates certificates that are fit to use for the current TLS
     * connection. If set to false, certificates are either generated as specified or the explicit
     * certificate is used
     */
    private Boolean autoAdjustCertificate = true;

    private Boolean autoAdjustSignatureAndHashAlgorithm = true;

    /**
     * A list of X509CertificateConfigurations that are used to automatically create the certificate
     * chain that is used in the CertificateMessage. The first config should be the leaf
     * certificate.
     */
    @XmlElement(name = "certificateConfig")
    @XmlElementWrapper
    private List<X509CertificateConfig> certificateChainConfig;

    /** List of filters to apply on workflow traces before serialization. */
    @XmlElement(name = "outputFilter")
    @XmlElementWrapper
    private List<FilterType> outputFilters;

    /**
     * Whether filters return a copy of the input workflow trace or overwrite it in place. While
     * copying would be preferred in general, overwriting might be desired in some scenarios for
     * better performance.
     */
    private Boolean applyFiltersInPlace = true;

    /**
     * Whether to keep explicit user settings in the workflow trace when applying filters or not.
     * Filters might override explicit user definitions in the filtered workflow trace. For example,
     * the DefaultFilter removes explicitly overwritten default connections. If this flag is true,
     * the user defined connections would be restored afterwards.
     */
    private Boolean filtersKeepUserSettings = true;

    /** If we receive records in the wrong order we will reorder them */
    private Boolean reorderReceivedDtlsRecords = true;

    /** Default value for ProtocolVersionFields */
    private ProtocolVersion highestProtocolVersion = ProtocolVersion.TLS12;

    /** The default connection parameters to use when running TLS-Client. */
    private OutboundConnection defaultClientConnection;

    /**
     * After executing a workflow trace, the final state of the TCP socket is stored inside the
     * context. By default the socket timeout for determining this state is set to 1ms. If execution
     * speed is not important, this can be set to true, so that the regular connection timeout
     * settings are used.
     */
    private Boolean receiveFinalTcpSocketStateWithTimeout = false;

    /**
     * Setting this to true results in multiple attempts to initialize a connection to the server
     * when a ClientTcpTransportHandler is used.
     */
    private Boolean retryFailedClientTcpSocketInitialization = false;

    /**
     * Setting this to true results in the Client transporthandlers trying to acquire a new port on
     * each connection attempt. Default behavior true so that reused ports are not an issue.
     */
    private Boolean resetClientSourcePort = true;

    /** The default connection parameters to use when running TLS-Server. */
    private InboundConnection defaultServerConnection;

    private RunningModeType defaultRunningMode = RunningModeType.CLIENT;

    /** If default generated WorkflowTraces should contain cookie exchange */
    private Boolean dtlsCookieExchange = true;

    /** If default generated WorkflowTraces should contain client Authentication */
    private Boolean clientAuthentication = false;

    /** If the ServerHello should contain all enabled extensions or only proposed ones */
    private Boolean respectClientProposedExtensions = false;

    /** Which Signature and Hash algorithms we support */
    @XmlElement(name = "defaultClientSupportedSignatureAndHashAlgorithm")
    @XmlElementWrapper
    private List<SignatureAndHashAlgorithm> defaultClientSupportedSignatureAndHashAlgorithms;

    /** Which Signature and Hash algorithms we support for Certificates */
    @XmlElement(name = "defaultClientSupportedCertificateSignAlgorithms")
    @XmlElementWrapper
    private List<SignatureAndHashAlgorithm> defaultClientSupportedCertificateSignAlgorithms;

    /** Which Cipher suites we support by default */
    @XmlElement(name = "defaultClientSupportedCipherSuite")
    @XmlElementWrapper
    private List<CipherSuite> defaultClientSupportedCipherSuites;

    /** Which Cipher suites we support by default */
    @XmlElement(name = "defaultServerSupportedCipherSuite")
    @XmlElementWrapper
    private List<CipherSuite> defaultServerSupportedCipherSuites;

    /** Which CSSL 2 Cipher suites we support by default */
    @XmlElement(name = "defaultServerSupportedSSL2CipherSuite")
    @XmlElementWrapper
    private List<SSL2CipherSuite> defaultServerSupportedSSL2CipherSuites;

    /** Default clientSupportedNamed groups */
    @XmlElement(name = "defaultClientNamedGroup")
    @XmlElementWrapper
    private List<NamedGroup> defaultClientNamedGroups;

    /** Default clientSupportedNamed groups */
    @XmlElement(name = "defaultServerNamedGroup")
    @XmlElementWrapper
    private List<NamedGroup> defaultServerNamedGroups;

    /** Supported ProtocolVersions by default */
    @XmlElement(name = "supportedVersion")
    @XmlElementWrapper
    private List<ProtocolVersion> supportedVersions;

    /** Which heartBeat mode we are in */
    private HeartbeatMode heartbeatMode = HeartbeatMode.PEER_ALLOWED_TO_SEND;

    /** Padding length for TLS 1.3 messages */
    private Integer defaultAdditionalPadding = 0;

    @XmlElement(name = "defaultSniHostname")
    @XmlElementWrapper
    private List<ServerNamePair> defaultSniHostnames =
            new LinkedList<>(
                    List.of(
                            new ServerNamePair(
                                    SniType.HOST_NAME.getValue(),
                                    "example.com".getBytes(US_ASCII))));

    /** Key type for KeyShareExtension */
    private NamedGroup defaultSelectedNamedGroup = NamedGroup.SECP256R1;

    @XmlElement
    @XmlJavaTypeAdapter(MapAdapter.class)
    private Map<NamedGroup, BigInteger> defaultKeySharePrivateMap = new HashMap<>();

    @XmlElement(name = "defaultClientKeyShareNamedGroup")
    @XmlElementWrapper
    private List<NamedGroup> defaultClientKeyShareNamedGroups;

    @XmlElement(name = "defaultClientKeyStoreEntry")
    @XmlElementWrapper
    private List<KeyShareStoreEntry> defaultClientKeyStoreEntries;

    private KeyShareStoreEntry defaultServerKeyShareEntry;

    private SniType sniType = SniType.HOST_NAME;

    private Integer preferredCertRsaKeySize = 2048;

    private Integer preferredCertDssKeySize = 2048;

    /** Determine if a KeyUpdate should be requested from peer */
    private KeyUpdateRequest defaultKeyUpdateRequestMode = KeyUpdateRequest.UPDATE_NOT_REQUESTED;

    /** Determine if CCS should be encrypted in TLS 1.3 if encryption is set up for record layer */
    private Boolean encryptChangeCipherSpecTls13 = false;

    /**
     * SessionTLSTicket for the SessionTLSTicketExtension. It's an empty session ticket since we
     * initiate a new connection.
     */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] tlsSessionTicket = new byte[0];

    /**
     * Renegotiation info for the RenegotiationInfo extension for the Client. It's an empty info
     * since we initiate a new connection.
     */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientRenegotiationInfo = new byte[0];

    /**
     * Renegotiation info for the RenegotiationInfo extension for the Client. It's an empty info
     * since we initiate a new connection.
     */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerRenegotiationInfo = new byte[0];

    /**
     * SignedCertificateTimestamp for the SignedCertificateTimestampExtension. It's an empty
     * timestamp, since the server sends it.
     */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultSignedCertificateTimestamp = new byte[0];

    /** TokenBinding default version. To be defined later. */
    private TokenBindingVersion defaultTokenBindingVersion = TokenBindingVersion.DRAFT_13;

    /** Default TokenBinding Key Parameters. */
    @XmlElement(name = "defaultTokenBindingKeyParameter")
    @XmlElementWrapper
    private List<TokenBindingKeyParameters> defaultTokenBindingKeyParameters;

    /** This is the request type of the CertificateStatusRequest extension */
    private CertificateStatusRequestType certificateStatusRequestExtensionRequestType =
            CertificateStatusRequestType.OCSP;

    /** This is the responder ID list of the CertificateStatusRequest extension */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] certificateStatusRequestExtensionResponderIDList = new byte[0];

    /** This is the request extension of the CertificateStatusRequest extension */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] certificateStatusRequestExtensionRequestExtension = new byte[0];

    /** Default ALPN announced protocols */
    @XmlElement(name = "defaultProposedAlpnProtocol")
    @XmlElementWrapper
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private List<String> defaultProposedAlpnProtocols;

    /** Default QuicTransportParameters */
    @XmlElement(name = "defaultQuicTransportParameters")
    private QuicTransportParameters defaultQuicTransportParameters;

    /** If true tries to decrypt the initial QUIC packets with own keys */
    private Boolean echoQuic = false;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultSelectedAlpnProtocol = AlpnProtocol.HTTP_2.getConstant();

    /** Default SRP Identifier */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] secureRemotePasswordExtensionIdentifier =
            "UserName".getBytes(Charset.forName("UTF-8"));

    /** Default SRTP extension protection profiles. */
    @XmlElement(name = "clientSupportedSrtpProtectionProfiles")
    @XmlElementWrapper
    private List<SrtpProtectionProfile> clientSupportedSrtpProtectionProfiles;

    /** SRTP extension protection profiles supported by the server. */
    @XmlElement(name = "serverSupportedSrtpProtectionProfiles")
    @XmlElementWrapper
    private List<SrtpProtectionProfile> serverSupportedSrtpProtectionProfiles;

    private SrtpProtectionProfile defaultSelectedSrtpProtectionProfile =
            SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80;

    /** Default SRTP extension master key identifier */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] secureRealTimeTransportProtocolMasterKeyIdentifier = new byte[0];

    /** Default user mapping extension hint type */
    private UserMappingExtensionHintType userMappingExtensionHintType =
            UserMappingExtensionHintType.UPN_DOMAIN_HINT;

    /** Default certificate type extension desired types */
    @XmlElement(name = "certificateTypeDesiredType")
    @XmlElementWrapper
    private List<CertificateType> certificateTypeDesiredTypes;

    /** Default client certificate type extension desired types */
    @XmlElement(name = "clientCertificateTypeDesiredType")
    @XmlElementWrapper
    private List<CertificateType> clientCertificateTypeDesiredTypes;

    /** Default server certificate type extension desired types */
    @XmlElement(name = "serverCertificateTypeDesiredType")
    @XmlElementWrapper
    private List<CertificateType> serverCertificateTypeDesiredTypes;

    /** Default client authz extension data format list */
    @XmlElement(name = "clientAuthzExtensionDataFormat")
    @XmlElementWrapper
    private List<AuthzDataFormat> clientAuthzExtensionDataFormat;

    /** Default state for the certificate type extension message. State "client" */
    private Boolean certificateTypeExtensionMessageState = true;

    /** Default sever authz extension data format list. */
    @XmlElement(name = "serverAuthzExtensionDataFormat")
    @XmlElementWrapper
    private List<AuthzDataFormat> serverAuthzExtensionDataFormat;

    /** Default trusted ca indication extension trusted CAs. */
    @XmlElement(name = "trustedCaIndicationExtensionAuthority")
    @XmlElementWrapper
    private List<TrustedAuthority> trustedCaIndicationExtensionAuthorities;

    /** Default state for the client certificate type extension message (state "client"). */
    private Boolean clientCertificateTypeExtensionMessageState = true;

    /** Default state for the cached info extension message (state "client"). */
    private Boolean cachedInfoExtensionIsClientState = true;

    /** Default cached objects for the cached info extension. */
    @XmlElement(name = "cachedObject")
    @XmlElementWrapper
    private List<CachedObject> cachedObjectList;

    /** Default certificate status request v2 extension request list. */
    @XmlElement(name = "statusRequestV2Request")
    @XmlElementWrapper
    private List<RequestItemV2> statusRequestV2RequestList;

    /** The Type of workflow trace that should be generated */
    private WorkflowTraceType workflowTraceType = null;

    /** If the Default generated workflowtrace should contain Application data send by servers */
    private Boolean serverSendsApplicationData = false;

    /** If we generate ClientHello with extensions in SSL */
    private Boolean addExtensionsInSSL = false;

    /** If we generate ClientHello with the ECPointFormat extension */
    private Boolean addECPointFormatExtension = true;

    /** If we generate ClientHello with the EllipticCurve extension */
    private Boolean addEllipticCurveExtension = true;

    /** If we generate ClientHello with the Heartbeat extension */
    private Boolean addHeartbeatExtension = false;

    /** If we generate ClientHello with the MaxFragmentLength extension */
    private Boolean addMaxFragmentLengthExtension = false;

    /** If we generate ClientHello with the RecordSizeLimit extension */
    private Boolean addRecordSizeLimitExtension = false;

    /** If we generate ClientHello with the ServerNameIndication extension */
    private Boolean addServerNameIndicationExtension = false;

    /** If we generate ClientHello with the SignatureAndHashAlgorithm extension */
    private Boolean addSignatureAndHashAlgorithmsExtension = true;

    /** If we generate ClientHello with the SignatureAlgorithmCert extension */
    private Boolean addSignatureAlgorithmsCertExtension = false;

    /** If we generate ClientHello with the SupportedVersion extension */
    private Boolean addSupportedVersionsExtension = false;

    /** If we generate ClientHello with the KeyShare extension */
    private Boolean addKeyShareExtension = false;

    /** If we generate ClientHello with the EarlyData extension */
    private Boolean addEarlyDataExtension = false;

    /** The maximum amount of early data included in the EarlyDataExtension */
    private Integer defaultMaxEarlyDataSize = 16384;

    /** If we generate ClientHello with the EncryptedServerNameIndication extension */
    private Boolean addEncryptedServerNameIndicationExtension = false;

    /** If we generate ClientHello with the PWDClear extension */
    private Boolean addPWDClearExtension = false;

    /** If we generate ClientHello with the PWDProtect extension */
    private Boolean addPWDProtectExtension = false;

    /** If we generate ClientHello with the PSKKeyExchangeModes extension */
    private Boolean addPSKKeyExchangeModesExtension = false;

    /** If we generate ClientHello with the PreSharedKey extension */
    private Boolean addPreSharedKeyExtension = false;

    /** If we generate ClientHello with the Padding extension */
    private Boolean addPaddingExtension = false;

    /** If we generate ClientHello with the ExtendedMasterSecret extension */
    private Boolean addExtendedMasterSecretExtension = false;

    /** If we generate ClientHello with the SessionTicketTLS extension */
    private Boolean addSessionTicketTLSExtension = false;

    /** If we generate ClientHello with the SessionTicketTLS extension */
    private Boolean addDebugExtension = false;

    /** If we generate ClientHello with extended Random Extension */
    private Boolean addExtendedRandomExtension = false;

    /** If we generate ClientHello with QuicTransportParameters Extension */
    private Boolean addQuicTransportParametersExtension = false;

    /** If we generate ClientHello with SignedCertificateTimestamp extension */
    private Boolean addSignedCertificateTimestampExtension = false;

    /** If we generate ClientHello with RenegotiationInfo extension */
    private Boolean addRenegotiationInfoExtension = true;

    /** If we generate ClientHello with TokenBinding extension. */
    private Boolean addTokenBindingExtension = false;

    /** Whether HTTP request should contain a cookie header field or not. */
    private Boolean addHttpCookie = false;

    /** Default cookie value to use if addHttpCookie is true. */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultHttpCookieName = "tls-attacker";

    /** Default cookie value to use if addHttpCookie is true. */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultHttpCookieValue = "42130912812";

    /** If we generate ClientHello with CertificateStatusRequest extension */
    private Boolean addCertificateStatusRequestExtension = false;

    /** If we generate ClientHello with ALPN extension */
    private Boolean addAlpnExtension = false;

    /** If we generate ClientHello with SRP extension */
    private Boolean addSRPExtension = false;

    /** If we generate ClientHello with SRTP extension */
    private Boolean addSRTPExtension = false;

    /** If we generate ClientHello with truncated hmac extension */
    private Boolean addTruncatedHmacExtension = false;

    /** If we generate ClientHello with user mapping extension */
    private Boolean addUserMappingExtension = false;

    /** If we generate ClientHello with certificate type extension */
    private Boolean addCertificateTypeExtension = false;

    /** If we generate ClientHello with client authz extension */
    private Boolean addClientAuthzExtension = false;

    /** If we generate ClientHello with server authz extension */
    private Boolean addServerAuthzExtension = false;

    /** If we generate ClientHello with client certificate type extension */
    private Boolean addClientCertificateTypeExtension = false;

    /** If we generate ClientHello with server certificate type extension */
    private Boolean addServerCertificateTypeExtension = false;

    /** If we generate ClientHello with encrypt then mac extension */
    private Boolean addEncryptThenMacExtension = false;

    /** If we generate ClientHello with cached info extension */
    private Boolean addCachedInfoExtension = false;

    /** If we generate ClientHello with client certificate url extension */
    private Boolean addClientCertificateUrlExtension = false;

    /** If we generate ClientHello with trusted ca indication extension */
    private Boolean addTrustedCaIndicationExtension = false;

    /** If we generate ClientHello with status request v2 extension */
    private Boolean addCertificateStatusRequestV2Extension = false;

    /** If we generate ClientHello with TLS 1.3 cookie extension */
    private Boolean addCookieExtension = false;

    /** Collect handshake messages and send in as few records as possible * */
    private Boolean sendHandshakeMessagesWithinSingleRecord = false;

    /** Default ConnectionID to use, if addConnectionIdExtension is true */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    @XmlElement(name = "defaultConnectionId")
    private byte[] defaultConnectionId = {0x01, 0x02, 0x03};

    /** Default DebugContent to use, if addDebugExtension is true */
    @XmlElement(name = "defaultDebugContent")
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultDebugContent = "TLS-Attacker Debug Content";

    /**
     * Default number of connection IDs requested when sending a RequestConnectionId message (DTLS
     * 1.3)
     */
    private Integer defaultNumberOfRequestedConnectionIds = 3;

    /** Usage in der NewConnectionId message */
    private ConnectionIdUsage defaultUsageOfSentConnectionIds = ConnectionIdUsage.CID_SPARE;

    /** If we generate a ClientHello / ServerHello with DTLS 1.2 ConnectionID extension */
    private Boolean addConnectionIdExtension = false;

    /** PSKKeyExchangeModes to be used in 0-RTT (or TLS 1.3 resumption) */
    @XmlElement(name = "pskKeyExchangeMode")
    @XmlElementWrapper
    List<PskKeyExchangeMode> pskKeyExchangeModes;

    /** The PSK to use. */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] psk = new byte[0];

    /** The client's early traffic secret. */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] clientEarlyTrafficSecret = new byte[128];

    /** The early secret of the session. */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] earlySecret = new byte[256];

    /** The cipher suite used for early data. */
    private CipherSuite earlyDataCipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;

    /** The psk used for early data (!= earlySecret or earlyTrafficSecret). */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] earlyDataPsk = new byte[256];

    /** Contains all values related to TLS 1.3 PSKs. */
    @XmlElement(name = "defaultPskSet")
    @XmlElementWrapper
    private List<PskSet> defaultPskSets = new LinkedList<>();

    /** Always includes at most 1 PSK in the PreShareKey Extension. */
    private Boolean limitPsksToOne = false;

    /**
     * If records are predefined for a SendAction, assign each message a predefined record and place
     * automatically generated ones in between.
     */
    private Boolean preserveMessageRecordRelation = false;

    /** Do we use a psk for our secrets? */
    private Boolean usePsk = false;

    /** Early data to be sent. */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] earlyData = ArrayConverter.hexStringToByteArray("544c532d41747461636b65720a");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] distinguishedNames = new byte[0];

    private Boolean enforceSettings = false;

    /** The maximum number of bytes that can be received during a receive process. Default: 2^24. */
    private Integer receiveMaximumBytes = 16777216;

    /**
     * If true, Random of the context is not seeded with an explicit value, thus client/server
     * randoms are not deterministic.
     */
    private Boolean stealthMode = false;

    private Boolean stopActionsAfterIOException = false;

    private Boolean stopTraceAfterUnexpected = false;

    /** ActionOptions that are automatically applied to Actions of the MessageFactory */
    @XmlElement(name = "messageFactoryActionOption")
    @XmlElementWrapper
    private List<ActionOption> messageFactoryActionOptions = new LinkedList<>();

    private BigInteger defaultServerEphemeralDhGenerator = BigInteger.valueOf(2);

    private BigInteger defaultServerEphemeralDhModulus =
            new BigInteger(
                    "5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807");

    private BigInteger defaultServerEphemeralDhPrivateKey = new BigInteger("FFFF", 16);

    private BigInteger defaultClientEphemeralDhPrivateKey = new BigInteger("FFFF", 16);

    private BigInteger defaultServerEphemeralDhPublicKey =
            new BigInteger(
                    "2043613254509771843465057207078304133427100053346630496863115304729422431506842297554370188431622336168084226893060531474609378481237396107127063278624858982135545329954888129900714249447398611399069380214077491792199889131147659097337451088584054931352640316306698530468089459265836208766829761530786550035554546801263324790398605318443686766315312672983302101280548433287949333943437948214799189911192606949101858307621640886413682299273130735853556255008467704876737231663242842259426239401780891543201358635180397430055997246351872086043137262555233050955216238105392009330462604912891943865361186717249962097299588875409587651544594728203293910128024102640696503192096755401014128136916889018704050784334709496695214785225237421325503031115105974843553040027247097092511319153606298406218024502785451855415341620633845851737579504653807158340552365430158715166515645118698024341396560621615465703434564793715203380646117");

    private BigInteger defaultClientEphemeralDhPublicKey =
            new BigInteger(
                    "2043613254509771843465057207078304133427100053346630496863115304729422431506842297554370188431622336168084226893060531474609378481237396107127063278624858982135545329954888129900714249447398611399069380214077491792199889131147659097337451088584054931352640316306698530468089459265836208766829761530786550035554546801263324790398605318443686766315312672983302101280548433287949333943437948214799189911192606949101858307621640886413682299273130735853556255008467704876737231663242842259426239401780891543201358635180397430055997246351872086043137262555233050955216238105392009330462604912891943865361186717249962097299588875409587651544594728203293910128024102640696503192096755401014128136916889018704050784334709496695214785225237421325503031115105974843553040027247097092511319153606298406218024502785451855415341620633845851737579504653807158340552365430158715166515645118698024341396560621615465703434564793715203380646117");

    private BigInteger defaultEcdsaNonce =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "60B420BB3851D9D47ACB933DBE70399BF6C92DA33AF01D4FB770E98C0325F41D3EBAF8986DA712C82BCD4D554BF0B54023C29B624DE9EF9C2F931EFC580F9AFB081B12E107B1E805F2B4F5F0F1D00C2D0F62634670921C505867FF20F6A8335E98AF8725385586B41FEFF205B4E05A000823F78B5F8F5C02439CE8F67A781D90CBE6BF1AE7F2BC40A49709A06C0E31499BF02969CA42D203E566BCC696DE08FA0102A0FD2E2330B0964ABB7C443020DE1CAD09BFD6381FFB94DAAFBB90C4ED91A0613AD1DC4B4703AF84C1D63B1A876921C6D5869D61CCB98ED13AE6C09A13FC91E14922F301CF8BCF934315A6049D2F07D983FAA91B8F4E7265ECB815A7CBAB"));

    private BigInteger defaultDsaNonce =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "349C55648DCF992F3F33E8026CFAC87C1D2BA075"));

    private GOSTCurve defaultSelectedGostCurve = GOSTCurve.GostR3410_2001_CryptoPro_XchB;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultApplicationMessageData = "Test";

    @XmlElement(name = "clientCertificateType")
    @XmlElementWrapper
    private List<ClientCertificateType> clientCertificateTypes;

    /** max payload length used in our application (not set by the spec) */
    private Integer heartbeatPayloadLength = 256;

    private Integer heartbeatPaddingLength = 256;

    /** How much padding bytes should be send by default */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    @XmlElement(name = "defaultPaddingExtensionBytes")
    private byte[] defaultPaddingExtensionBytes = new byte[] {0, 0, 0, 0, 0, 0};

    /** How long should our DTLSCookies be by default */
    private Integer dtlsDefaultCookieLength = 20;

    /**
     * Configures the maximum fragment length. This should not be confused with MTU (which includes
     * the IP, UDP, record and DTLS headers).
     */
    private Integer dtlsMaximumFragmentLength = 1400;

    private Integer quicMaximumFrameSize = 1100;

    private WorkflowExecutorType workflowExecutorType = WorkflowExecutorType.DEFAULT;

    /** Does not mix messages with different message types in a single record */
    private Boolean flushOnMessageTypeChange = true;

    /**
     * If there is not enough space in the defined fragments, new fragments are dynamically added if
     * not set, protocolmessage bytes that wont fit are discarded
     */
    private Boolean createFragmentsDynamically = true;

    /**
     * If there is not enough space in the defined records, new records are dynamically added if not
     * set, protocol message bytes that wont fit are discarded
     */
    private Boolean createRecordsDynamically = true;

    /** Every fragment will be sent in one individual transport packet */
    private Boolean individualTransportPacketsForFragments = false;

    /** If we should wait after sending one transport packet [ADD FOR LAYER!] */
    private Integer individualTransportPacketCooldown = 0;

    /**
     * If this value is set the default workflowExecutor will remove all runtime values from the
     * workflow trace and will only keep the relevant information
     */
    private Boolean resetWorkflowTracesBeforeSaving = false;

    /** If the WorkflowExecutor should take care of the connection opening */
    private Boolean workflowExecutorShouldOpen = true;

    private Boolean stopReceivingAfterFatal = false;

    /** If the WorkflowExecutor should take care of the connection closing */
    private Boolean workflowExecutorShouldClose = true;

    private Boolean stopActionsAfterFatal = false;

    private Boolean stopActionsAfterQuicConnectionClose = true;

    /**
     * If the WorkflowExecutor should take care of terminating the connection with a Alert(fatal,
     * close_notify) message
     */
    private Boolean finishWithCloseNotify = false;

    /**
     * In DTLS, TLS-Attacker will not process further ChangeCipherSpec messages except the first
     * received per epoch value
     */
    private Boolean ignoreRetransmittedCcsInDtls = false;

    /** If retransmissions are received in DTLS should they included to the workflow trace */
    private Boolean addRetransmissionsToWorkflowTraceInDtls = false;

    /**
     * How many retransmissions should be executed during the handshake for UDP based protocols e.g.
     * DTLS or QUIC
     */
    private Integer maxUDPRetransmissions = 3;

    private Boolean expectHandshakeDoneQuicFrame = false;

    private Boolean isQuic = false;

    private Boolean quicRetryFlowRequired = false;

    private QuicVersion quicVersion = QuicVersion.VERSION_1;

    private byte[] defaultQuicNewToken =
            ArrayConverter.hexStringToByteArray(
                    "AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFF");

    private byte[] defaultQuicPathChallange = ArrayConverter.hexStringToByteArray("AABBCCDD");

    private Boolean stopActionsAfterWarning = false;

    /** This CipherSuite will be used if no cipherSuite has been negotiated yet */
    private CipherSuite defaultSelectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

    private CertificateType defaultSelectedServerCertificateType = CertificateType.X509;

    private CertificateType defaultSelectedClientCertificateType = CertificateType.X509;

    private SSL2CipherSuite defaultSSL2CipherSuite = SSL2CipherSuite.SSL_CK_RC4_128_WITH_MD5;

    @XmlElement(name = "defaultServerSupportedPointFormat")
    @XmlElementWrapper
    private List<ECPointFormat> defaultServerSupportedPointFormats;

    @XmlElement(name = "defaultClientSupportedPointFormat")
    @XmlElementWrapper
    private List<ECPointFormat> defaultClientSupportedPointFormats;

    @XmlElement(name = "defaultServerSupportedSignatureAndHashAlgorithm")
    @XmlElementWrapper
    private List<SignatureAndHashAlgorithm> defaultServerSupportedSignatureAndHashAlgorithms;

    @XmlElement(name = "defaultServerSupportedCertificateSignAlgorithms")
    @XmlElementWrapper
    private List<SignatureAndHashAlgorithm> defaultServerSupportedCertificateSignAlgorithms;

    private SignatureAndHashAlgorithm defaultSelectedSignatureAndHashAlgorithm =
            SignatureAndHashAlgorithm.RSA_SHA1;

    private SignatureAndHashAlgorithm defaultSelectedSignatureAlgorithmCert =
            SignatureAndHashAlgorithm.RSA_SHA1;

    private ProtocolVersion defaultLastRecordProtocolVersion = ProtocolVersion.TLS10;

    private ProtocolVersion defaultSelectedProtocolVersion = ProtocolVersion.TLS12;

    private ProtocolVersion defaultHighestClientProtocolVersion = ProtocolVersion.TLS12;

    /**
     * Both methods of limiting record size as defined in RFC 3546 (MaximumFragmentLength extension)
     * and RFC 8449 (RecordSizeLimit extension)
     */
    private MaxFragmentLength defaultMaxFragmentLength = MaxFragmentLength.TWO_12;

    private Integer defaultAssumedMaxReceiveLimit = RecordSizeLimit.DEFAULT_MAX_RECORD_DATA_SIZE;

    private Integer defaultMaxRecordData = RecordSizeLimit.DEFAULT_MAX_RECORD_DATA_SIZE;

    private Integer inboundRecordSizeLimit = RecordSizeLimit.DEFAULT_MAX_RECORD_DATA_SIZE;

    private HeartbeatMode defaultHeartbeatMode = HeartbeatMode.PEER_ALLOWED_TO_SEND;

    @XmlElement(name = "defaultClientSupportedCompressionMethod")
    @XmlElementWrapper
    private List<CompressionMethod> defaultClientSupportedCompressionMethods;

    @XmlElement(name = "defaultServerSupportedCompressionMethod")
    @XmlElementWrapper
    private List<CompressionMethod> defaultServerSupportedCompressionMethods;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultMasterSecret = new byte[48];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultPreMasterSecret = new byte[0];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientExtendedRandom =
            ArrayConverter.hexStringToByteArray(
                    "AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerExtendedRandom =
            ArrayConverter.hexStringToByteArray(
                    "AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientRandom =
            ArrayConverter.hexStringToByteArray(
                    "00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerRandom =
            ArrayConverter.hexStringToByteArray(
                    "00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientSessionId = new byte[0];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientTicketResumptionSessionId =
            ArrayConverter.hexStringToByteArray(
                    "332CAC09A5C56974E3D49C0741F396C5F1C90B41529DD643485E65B1C0619D2B");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerSessionId = new byte[0];

    private CompressionMethod defaultSelectedCompressionMethod = CompressionMethod.NULL;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] dtlsDefaultCookie = new byte[0];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultExtensionCookie = new byte[0];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultCertificateRequestContext = new byte[0];

    private PRFAlgorithm defaultPRFAlgorithm = PRFAlgorithm.TLS_PRF_LEGACY;

    private AlertDescription defaultAlertDescription = AlertDescription.CLOSE_NOTIFY;

    private AlertLevel defaultAlertLevel = AlertLevel.WARNING;

    private NamedGroup defaultEcCertificateCurve = NamedGroup.SECP256R1;

    private Point defaultClientEphemeralEcPublicKey =
            Point.createPoint(
                    new BigInteger(
                            "42877656971275811310262564894490210024759287182177196162425349131675946712428"),
                    new BigInteger(
                            "61154801112014214504178281461992570017247172004704277041681093927569603776562"),
                    defaultSelectedNamedGroup.getGroupParameters());

    private Point defaultServerEphemeralEcPublicKey =
            Point.createPoint(
                    new BigInteger(
                            "42877656971275811310262564894490210024759287182177196162425349131675946712428"),
                    new BigInteger(
                            "61154801112014214504178281461992570017247172004704277041681093927569603776562"),
                    defaultSelectedNamedGroup.getGroupParameters());

    private BigInteger defaultServerEphemeralEcPrivateKey = new BigInteger("3");

    private BigInteger defaultClientEphemeralEcPrivateKey = new BigInteger("3");

    private BigInteger defaultServerEphemeralRsaExportPublicKey = new BigInteger("65537");

    private BigInteger defaultServerEphemeralRsaExportPrivateKey =
            new BigInteger(
                    "7dc0cb485a3edb56811aeab12cdcda8e48b023298dd453a37b4d75d9e0bbba27c98f0e4852c16fd52341ffb673f64b580b7111abf14bf323e53a2dfa92727364ddb34f541f74a478a077f15277c013606aea839307e6f5fec23fdd72506feea7cbe362697949b145fe8945823a39a898ac6583fc5fbaefa1e77cbc95b3b475e66106e92b906bdbb214b87bcc94020f317fc1c056c834e9cee0ad21951fbdca088274c4ef9d8c2004c6294f49b370fb249c1e2431fb80ce5d3dc9e342914501ef4c162e54e1ee4fed9369b82afc00821a29f4979a647e60935420d44184d98f9cb75122fb604642c6d1ff2b3a51dc32eefdc57d9a9407ad6a06d10e83e2965481",
                    16);

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultPSKKey = ArrayConverter.hexStringToByteArray("1a2b3c4d");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultPSKIdentity = "Client_Identity".getBytes(Charset.forName("UTF-8"));

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultPSKIdentityHint = new byte[0];

    private BigInteger defaultSRPModulus =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"));

    private BigInteger defaultSRPGenerator = new BigInteger("2");

    private BigInteger defaultSRPServerPrivateKey = new BigInteger("3");

    private BigInteger defaultSRPClientPrivateKey = new BigInteger("5");

    private BigInteger defaultSRPServerPublicKey =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "AC47983DEB1698D9A9029E8F7B39092F441DDD72C56D3A63F236E1CF6CEE839937AB5FD69F8CEBBA64C210170A59B2526ED34B9DD83EF86DF7899DF68297844B15E6F2D1BD2448640D32A48220E6343875976A268F28D25174C37D8DC19F2BA5A35301CEED689206FA91CE7A172D908B821DF8C760918E6A5D1C0CFA76AF503B"));

    private BigInteger defaultSRPClientPublicKey =
            new BigInteger(1, ArrayConverter.hexStringToByteArray("25C843"));

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultSRPServerSalt = ArrayConverter.hexStringToByteArray("AABBCCDD");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultSRPIdentity = "UserName".getBytes(Charset.forName("UTF-8"));

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultSRPPassword = "Password".getBytes(Charset.forName("UTF-8"));

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientHandshakeTrafficSecret = new byte[32];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerHandshakeTrafficSecret = new byte[32];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientApplicationTrafficSecret = new byte[32];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerApplicationTrafficSecret = new byte[32];

    private BigInteger defaultServerEphemeralRsaExportModulus =
            new BigInteger(
                    "00e208ff3431b8d1f6c48d9bb93c76a9c7f5693ada3eb45fa12581d2203a97246a5ceed7cf8d8fc1d6136225545855dd41581543cecba0b4a5776f90d05a0059ff",
                    16);

    private BigInteger defaultServerEphemeralDhExportGenerator = new BigInteger("2");

    private BigInteger defaultServerEphemeralDhExportModulus =
            new BigInteger(
                    "0090e6a3f16f2c9325a8a036d9bd96d69ae2b6caa59fd7d4cce729b225f8849a14d0fb5939102ba44ed54f26c186e1ad243d58a1a4542ce1adffd482e8f85ef663",
                    16);

    private BigInteger defaultServerEphemeralDhExportPublicKey =
            new BigInteger(
                    "2530802253db34a8106584c96a066050310bd3b2eb11c71dd7095638eef4b7961892b13b2c983cc31635c49982b485fe837be0ba9d7f75ff72e2cae0f4c1b090",
                    16);

    private BigInteger defaultServerEphemeralDhExportPrivateKey =
            new BigInteger(
                    "4ba017c0142c0df8fe5f8da8f4046c0933486730b155f1b09bd611c09863b72ad9aec3782d9379883c4a291c748c530f433207f740e0db5f67748c2c2dde2866",
                    16);

    private TokenBindingType defaultTokenBindingType = TokenBindingType.PROVIDED_TOKEN_BINDING;

    private Point defaultTokenBindingECPublicKey =
            Point.createPoint(
                    new BigInteger(
                            "42877656971275811310262564894490210024759287182177196162425349131675946712428"),
                    new BigInteger(
                            "61154801112014214504178281461992570017247172004704277041681093927569603776562"),
                    defaultSelectedNamedGroup.getGroupParameters());

    private BigInteger defaultTokenBindingRsaPublicKey = new BigInteger("65537");

    private BigInteger defaultTokenBindingRsaPrivateKey =
            new BigInteger(
                    "89489425009274444368228545921773093919669586065884257445497854456487674839629818390934941973262879616797970608917283679875499331574161113854088813275488110588247193077582527278437906504015680623423550067240042466665654232383502922215493623289472138866445818789127946123407807725702626644091036502372545139713");

    private BigInteger defaultTokenBindingEcPrivateKey = new BigInteger("3");

    private BigInteger defaultTokenBindingRsaModulus =
            new BigInteger(
                    "145906768007583323230186939349070635292401872375357164399581871019873438799005358938369571402670149802121818086292467422828157022922076746906543401224889672472407926969987100581290103199317858753663710862357656510507883714297115637342788911463535102712032765166518411726859837988672111837205085526346618740053");

    private Boolean useFreshRandom = true;

    private ChooserType chooserType = ChooserType.DEFAULT;

    private Boolean useAllProvidedDtlsFragments = false;

    private Boolean useAllProvidedRecords = false;

    private Boolean useAllProvidedQuicPackets = false;

    /**
     * requestPath to use in LocationHeader if none is saved during the connection, e.g. no received
     * HttpRequestMessage or httpParsing is disabled
     */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultHttpsLocationPath = "/";

    /** requestPath to use in https requests */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultHttpsRequestPath = "/robots.txt";

    private Integer defaultMaxHttpLength = 65536; // 2^16

    private StarttlsType starttlsType = StarttlsType.NONE;

    /**
     * By default, the Session ID is overwritten, if (1) the server receives an empty Session Ticket
     * (it answers with an empty Server SID) (2) the client presents a sessionTicket
     * (defaultClientTicketResumptionSessionId is used). Unset this flag if you want to modify the
     * SessionID.
     */
    private Boolean overrideSessionIdForTickets = true;

    /**
     * The Ticket Lifetime Hint, Ticket Key and Ticket Key Name used in the Extension defined in
     * RFC5077, followed by additional TLS 1.3 draft 21 NewSessionTicket parameters.
     */
    private Long sessionTicketLifetimeHint = 7200L;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] sessionTicketEncryptionKey =
            ArrayConverter.hexStringToByteArray(
                    "536563757265535469636b65744b6579"); // SecureSTicketKey

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] sessionTicketKeyHMAC =
            ArrayConverter.hexStringToByteArray(
                    "536563757265535469636b65744b6579536563757265535469636b65744b6579"); // SecureSTicketKeySecureSTicketKey

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] sessionTicketKeyName =
            ArrayConverter.hexStringToByteArray("544c532d41747461636b6572204b6579"); // TLS-Attacker

    private CipherAlgorithm sessionTicketCipherAlgorithm = CipherAlgorithm.AES_128_CBC;

    private MacAlgorithm sessionTicketMacAlgorithm = MacAlgorithm.HMAC_SHA256;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultSessionTicketAgeAdd = ArrayConverter.hexStringToByteArray("cb8dbe8e");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultSessionTicketNonce = ArrayConverter.hexStringToByteArray("00");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultSessionTicketIdentity =
            ArrayConverter.hexStringToByteArray(
                    "5266d21abe0f5156106eb1f0ec54a48a90fbc136de990a8881192211cc83aa7992ceb67d7a40b3f304fdea87e4ca61042c19641fd7493975ec69a3ec3f5fb6404aa4ac5acd5efbea15d454d89888a46fc4e6c6b9a3e0ee08ea21538372ced8d0aca453ceae44ce372a5388ab4cef67c5eae8cc1c72735d2646c19b2c50a4ee9bc97e70c6b57cab276a11a59fc5cbe0f5d2519e164fbf9f07a9dd053bcfc08939b475c7a2e76f04ef2a06cc9672bd4034");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultLastClientHello = new byte[32];

    /** ClientAuthentication Type, not fully implemented yet */
    private ClientAuthenticationType clientAuthenticationType = ClientAuthenticationType.ANONYMOUS;

    /** If we should add ccs message to automatically generated handshakes (tls 1.3 only) */
    private Boolean tls13BackwardsCompatibilityMode = true;

    /** Use username from the example of RFC8492 */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultClientPWDUsername = "fred";

    /** Group used to encrypt the username in TLS_ECCPWD */
    private NamedGroup defaultPWDProtectGroup = NamedGroup.SECP256R1;

    private BigInteger defaultServerPWDProtectPrivateKey =
            new BigInteger(
                    "191991257030464195512760799659436374116556484140110877679395918219072292938297573720808302564562486757422301181089761");

    private Point defaultServerPWDProtectPublicKey =
            Point.createPoint(
                    new BigInteger(
                            "18331185786522319349444255540874590232255475110717040504630785378857839293510"),
                    new BigInteger(
                            "77016287303447444409379355974404854219241223376914775755121063765271326101171"),
                    defaultSelectedNamedGroup.getGroupParameters());

    private BigInteger defaultServerPWDProtectRandomSecret =
            new BigInteger(
                    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");

    /** Use password from the example of RFC8492 */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultPWDPassword = "barney";

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerPWDPrivate =
            ArrayConverter.hexStringToByteArray(
                    "21d99d341c9797b3ae72dfd289971f1b74ce9de68ad4b9abf54888d8f6c5043c");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerPWDMask =
            ArrayConverter.hexStringToByteArray(
                    "0d96ab624d082c71255be3648dcd303f6ab0ca61a95034a553e3308d1d3744e5");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientPWDPrivate =
            ArrayConverter.hexStringToByteArray(
                    "171de8caa5352d36ee96a39979b5b72fa189ae7a6a09c77f7b438af16df4a88b");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultClientPWDMask =
            ArrayConverter.hexStringToByteArray(
                    "4f745bdfc295d3b38429f7eb3025a48883728b07d88605c0ee202316a072d1bd");

    /** Use salt from the example of RFC8492, should be 32 octets */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultServerPWDSalt =
            ArrayConverter.hexStringToByteArray(
                    "963c77cdc13a2a8d75cdddd1e0449929843711c21d47ce6e6383cdda37e47da3");

    private ECPointFormat defaultSelectedPointFormat = ECPointFormat.UNCOMPRESSED;

    /** The DNS server to use for DNS queries (e.g. ech keys) */
    private String defaultDnsServer = "8.8.8.8";

    /** Private Key of the Client for the EncryptedServerNameIndication extension. */
    private BigInteger defaultEsniClientPrivateKey =
            new BigInteger(
                    "191991257030464195512760799659436374116556484140110877679395918219072292938297573720808302564562486757422301181089761");

    /** Supported Cipher suites for EncryptedServerNameIndication extension. */
    @XmlElement(name = "clientSupportedEsniCipherSuite")
    @XmlElementWrapper
    private List<CipherSuite> clientSupportedEsniCipherSuites = new LinkedList<>();

    /** Supported Groups for EncryptedServerNameIndication extension. */
    @XmlElement(name = "clientSupportedEsniNamedGroup")
    @XmlElementWrapper
    private List<NamedGroup> clientSupportedEsniNamedGroups = new LinkedList<>();

    /** KeyPairs for Server with EncryptedServerNameIndication extension. */
    @XmlElement(name = "esniServerKeyPair")
    @XmlElementWrapper
    private List<KeyShareEntry> esniServerKeyPairs = new LinkedList<>();

    /** Default values for EncryptedServerNameIndication extension. */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultEsniClientNonce =
            ArrayConverter.hexStringToByteArray("a7284c9a52f15c13644b947261774657");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultEsniServerNonce =
            ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultEsniRecordBytes =
            ArrayConverter.hexStringToByteArray(
                    "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050000");

    private EsniDnsKeyRecordVersion defaultEsniRecordVersion =
            EsniVersion.DRAFT_2.getDnsKeyRecordVersion();

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultEsniRecordChecksum = ArrayConverter.hexStringToByteArray("00124b2a");

    @XmlElement(name = "defaultEsniServerKeyShareEntry")
    @XmlElementWrapper
    private List<KeyShareStoreEntry> defaultEsniServerKeyShareEntries = new LinkedList<>();

    @XmlElement(name = "defaultEsniServerCipherSuite")
    @XmlElementWrapper
    private List<CipherSuite> defaultEsniServerCipherSuites = new LinkedList<>();

    private Integer defaultEsniPaddedLength = 260;

    private Long defaultEsniNotBefore = 1582655135231L;

    private Long defaultEsniNotAfter = 1582655135231L + 2592000000L;

    @XmlElement(name = "defaultEsniExtension")
    @XmlElementWrapper
    private List<ExtensionType> defaultEsniExtensions = new LinkedList<>();

    /** Private Key of the Client for the EncryptedClientHello extension. */
    private BigInteger defaultEchClientPrivateKey =
            new BigInteger(
                    "191991257030464195512760799659436374116556484140110877679395918219072292938297573720808302564562486757422301181089761");

    /** Default value of a server's public key */
    private BigInteger defaultEchServerPrivateKey =
            new BigInteger(
                    "-1673869334575128978734767576405071540980308529037586990006706167463937836529");

    /** Default algorithm values for ECH */
    private EchConfig defaultEchConfig;

    /** If we generate ClientHello with the EncryptedClientHello extension */
    private Boolean addEncryptedClientHelloExtension = false;

    /** Padding for the list of alpn values */
    private Integer defaultMaxEchAlpnPadding = 25;

    private Boolean acceptOnlyFittingDtlsFragments = false;

    /** DTLS 1.3 */
    private Boolean canSkipMessageSequenceNumber = false;

    private Boolean acceptContentRewritingDtlsFragments = true;

    private Boolean writeKeylogFile = false;

    private String keylogFilePath = null;

    /**
     * 16-bit encoding instead of 8-bit encoding for the sequence number in the DTLS 1.3 unified
     * header
     */
    private Boolean useDtls13HeaderSeqNumSizeLongEncoding = true;

    /** In DTLS 1.3, TLS-Attacker retransmits only records that have not yet been acknowledged */
    private Boolean retransmitAcknowledgedRecordsInDtls13 = false;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultRsaSsaPssSalt =
            ArrayConverter.hexStringToByteArray(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    public Config() {
        this.certificateChainConfig = new LinkedList<>();
        List<Pair<X500AttributeType, String>> rdn = new LinkedList<>();
        rdn.add(
                new Pair<>(
                        X500AttributeType.COMMON_NAME, "Attacker CA - Global Insecurity Provider"));
        rdn.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
        rdn.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
        X509CertificateConfig caConfig = new X509CertificateConfig();
        caConfig.setIssuer(rdn);
        caConfig.setSubject(rdn);
        byte[] serialNumber =
                ArrayConverter.hexStringToByteArray("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF");
        caConfig.setSerialNumber(new BigInteger(serialNumber));

        X509CertificateConfig leafConfig = new X509CertificateConfig();
        leafConfig.setIssuer(rdn);
        rdn = new LinkedList<>();
        rdn.add(new Pair<>(X500AttributeType.COMMON_NAME, "tls-attacker.com"));
        rdn.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));

        leafConfig.setSubject(rdn);
        serialNumber =
                ArrayConverter.hexStringToByteArray("0F1F2F34F5F6F7F8F9F0F0F9F8F7F6F5F4F3F2F1");
        leafConfig.setSerialNumber(new BigInteger(serialNumber));

        certificateChainConfig.add(leafConfig);
        certificateChainConfig.add(caConfig);
        defaultLayerConfiguration = StackConfiguration.TLS;
        defaultClientConnection = new OutboundConnection("client", 443, "localhost");
        defaultServerConnection = new InboundConnection("server", 443, "localhost");
        workflowTraceType = WorkflowTraceType.DYNAMIC_HANDSHAKE;
        clientSupportedSrtpProtectionProfiles = new LinkedList<>();
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32);
        clientSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32);
        clientSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80);
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM);
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM);
        clientSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_AES_128_GCM);
        clientSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_AES_256_GCM);
        clientSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_ARIA_128_GCM);
        clientSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_ARIA_256_GCM);
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_32);
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_80);
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_32);
        clientSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_80);

        serverSupportedSrtpProtectionProfiles = new LinkedList<>();
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80);
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32);
        serverSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_32);
        serverSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_NULL_HMAC_SHA1_80);
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM);
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM);
        serverSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_AES_128_GCM);
        serverSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_AES_256_GCM);
        serverSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_ARIA_128_GCM);
        serverSupportedSrtpProtectionProfiles.add(SrtpProtectionProfile.SRTP_AEAD_ARIA_256_GCM);
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_32);
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_128_CTR_HMAC_SHA1_80);
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_32);
        serverSupportedSrtpProtectionProfiles.add(
                SrtpProtectionProfile.SRTP_ARIA_256_CTR_HMAC_SHA1_80);

        defaultEsniServerKeyShareEntries.add(
                new KeyShareStoreEntry(
                        NamedGroup.ECDH_X25519,
                        ArrayConverter.hexStringToByteArray(
                                "fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412")));
        defaultEsniServerCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        defaultClientSupportedSignatureAndHashAlgorithms = new LinkedList<>();
        defaultClientSupportedSignatureAndHashAlgorithms.addAll(
                SignatureAndHashAlgorithm.getImplemented());
        defaultClientSupportedCertificateSignAlgorithms = new LinkedList<>();
        defaultClientSupportedCertificateSignAlgorithms.addAll(
                SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());
        defaultClientSupportedCompressionMethods = new LinkedList<>();
        defaultClientSupportedCompressionMethods.add(CompressionMethod.NULL);
        defaultServerSupportedCompressionMethods = new LinkedList<>();
        defaultServerSupportedCompressionMethods.add(CompressionMethod.NULL);
        defaultClientSupportedCipherSuites = new LinkedList<>();
        defaultClientSupportedCipherSuites.addAll(CipherSuite.getImplemented());
        defaultServerSupportedCipherSuites = new LinkedList<>();
        defaultServerSupportedCipherSuites.addAll(CipherSuite.getImplemented());
        clientSupportedEsniCipherSuites = new LinkedList<>();
        clientSupportedEsniCipherSuites.addAll(CipherSuite.getImplemented());
        defaultServerSupportedSSL2CipherSuites = new LinkedList<>();
        defaultServerSupportedSSL2CipherSuites.addAll(Arrays.asList(SSL2CipherSuite.values()));
        defaultClientNamedGroups = NamedGroup.getImplemented();
        defaultServerNamedGroups = NamedGroup.getImplemented();
        clientSupportedEsniNamedGroups = NamedGroup.getImplemented();
        clientCertificateTypes = new LinkedList<>();
        clientCertificateTypes.add(ClientCertificateType.RSA_SIGN);
        supportedVersions = new LinkedList<>();
        supportedVersions.add(ProtocolVersion.TLS13);
        defaultTokenBindingKeyParameters = new LinkedList<>();
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.ECDSAP256);
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.RSA2048_PKCS1_5);
        defaultTokenBindingKeyParameters.add(TokenBindingKeyParameters.RSA2048_PSS);
        defaultServerSupportedSignatureAndHashAlgorithms = new LinkedList<>();
        defaultServerSupportedSignatureAndHashAlgorithms.addAll(
                SignatureAndHashAlgorithm.getImplemented());
        defaultServerSupportedCertificateSignAlgorithms = new LinkedList<>();
        defaultServerSupportedCertificateSignAlgorithms.addAll(
                SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());
        defaultServerSupportedPointFormats = new LinkedList<>();
        defaultClientSupportedPointFormats = new LinkedList<>();
        defaultServerSupportedPointFormats.add(ECPointFormat.UNCOMPRESSED);
        defaultClientSupportedPointFormats.add(ECPointFormat.UNCOMPRESSED);
        certificateTypeDesiredTypes = new LinkedList<>();
        certificateTypeDesiredTypes.add(CertificateType.OPEN_PGP);
        certificateTypeDesiredTypes.add(CertificateType.X509);
        clientAuthzExtensionDataFormat = new LinkedList<>();
        clientAuthzExtensionDataFormat.add(AuthzDataFormat.X509_ATTR_CERT);
        clientAuthzExtensionDataFormat.add(AuthzDataFormat.SAML_ASSERTION);
        clientAuthzExtensionDataFormat.add(AuthzDataFormat.X509_ATTR_CERT_URL);
        clientAuthzExtensionDataFormat.add(AuthzDataFormat.SAML_ASSERTION_URL);
        serverAuthzExtensionDataFormat = new LinkedList<>();
        serverAuthzExtensionDataFormat.add(AuthzDataFormat.X509_ATTR_CERT);
        serverAuthzExtensionDataFormat.add(AuthzDataFormat.SAML_ASSERTION);
        serverAuthzExtensionDataFormat.add(AuthzDataFormat.X509_ATTR_CERT_URL);
        serverAuthzExtensionDataFormat.add(AuthzDataFormat.SAML_ASSERTION_URL);
        clientCertificateTypeDesiredTypes = new LinkedList<>();
        clientCertificateTypeDesiredTypes.add(CertificateType.OPEN_PGP);
        clientCertificateTypeDesiredTypes.add(CertificateType.X509);
        clientCertificateTypeDesiredTypes.add(CertificateType.RAW_PUBLIC_KEY);
        serverCertificateTypeDesiredTypes = new LinkedList<>();
        serverCertificateTypeDesiredTypes.add(CertificateType.OPEN_PGP);
        serverCertificateTypeDesiredTypes.add(CertificateType.X509);
        serverCertificateTypeDesiredTypes.add(CertificateType.RAW_PUBLIC_KEY);
        cachedObjectList = new LinkedList<>();
        trustedCaIndicationExtensionAuthorities = new LinkedList<>();
        statusRequestV2RequestList = new LinkedList<>();
        outputFilters = new ArrayList<>();
        outputFilters.add(FilterType.DEFAULT);
        applyFiltersInPlace = false;
        filtersKeepUserSettings = true;
        defaultClientKeyStoreEntries = new LinkedList<>();
        defaultClientKeyStoreEntries.add(
                new KeyShareStoreEntry(
                        NamedGroup.ECDH_X25519,
                        ArrayConverter.hexStringToByteArray(
                                "2A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C")));
        defaultClientKeyShareNamedGroups = new LinkedList<>();
        defaultClientKeyShareNamedGroups.add(NamedGroup.ECDH_X25519);
        defaultServerKeyShareEntry =
                new KeyShareStoreEntry(
                        NamedGroup.ECDH_X25519,
                        ArrayConverter.hexStringToByteArray(
                                "2A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C"));
        defaultEchConfig = EchConfig.createDefaultEchConfig();
        pskKeyExchangeModes = new LinkedList<>();
        pskKeyExchangeModes.add(PskKeyExchangeMode.PSK_KE);
        pskKeyExchangeModes.add(PskKeyExchangeMode.PSK_DHE_KE);
        defaultPskSets = new LinkedList<>();
        defaultProposedAlpnProtocols = new LinkedList<>();
        defaultProposedAlpnProtocols.add(AlpnProtocol.HTTP_2.getConstant());
        defaultQuicTransportParameters = QuicTransportParameters.getDefaultParameters();
    }

    public void setDefaultRsaSsaPssSalt(byte[] salt) {
        System.arraycopy(defaultRsaSsaPssSalt, 0, salt, 0, defaultRsaSsaPssSalt.length);
    }

    public byte[] getDefaultRsaSsaPssSalt() {
        return defaultRsaSsaPssSalt;
    }

    public Point getDefaultClientEphemeralEcPublicKey() {
        return defaultClientEphemeralEcPublicKey;
    }

    public void setDefaultClientEphemeralEcPublicKey(Point defaultClientEcPublicKey) {
        this.defaultClientEphemeralEcPublicKey = defaultClientEcPublicKey;
    }

    public Point getDefaultServerEphemeralEcPublicKey() {
        return defaultServerEphemeralEcPublicKey;
    }

    public void setDefaultServerEphemeralEcPublicKey(Point defaultServerEcPublicKey) {
        this.defaultServerEphemeralEcPublicKey = defaultServerEcPublicKey;
    }

    public Boolean getAutoAdjustCertificate() {
        return autoAdjustCertificate;
    }

    public void setAutoAdjustCertificate(Boolean autoAdjustCertificate) {
        this.autoAdjustCertificate = autoAdjustCertificate;
    }

    public BigInteger getDefaultEcdsaNonce() {
        return defaultEcdsaNonce;
    }

    public void setDefaultEcdsaNonce(BigInteger defaultEcdsaNonce) {
        this.defaultEcdsaNonce = defaultEcdsaNonce;
    }

    public BigInteger getDefaultDsaNonce() {
        return defaultDsaNonce;
    }

    public void setDefaultDsaNonce(BigInteger defaultDsaNonce) {
        this.defaultDsaNonce = defaultDsaNonce;
    }

    public List<X509CertificateConfig> getCertificateChainConfig() {
        return certificateChainConfig;
    }

    public void setCertificateChainConfig(List<X509CertificateConfig> certificateChainConfig) {
        this.certificateChainConfig = certificateChainConfig;
    }

    public List<CertificateBytes> getDefaultExplicitCertificateChain() {
        return defaultExplicitCertificateChain;
    }

    public void setDefaultExplicitCertificateChain(
            List<CertificateBytes> defaultExplicitCertificateChain) {
        this.defaultExplicitCertificateChain = defaultExplicitCertificateChain;
    }

    public String getDefaultSelectedAlpnProtocol() {
        return defaultSelectedAlpnProtocol;
    }

    public void setDefaultSelectedAlpnProtocol(String defaultSelectedAlpnProtocol) {
        this.defaultSelectedAlpnProtocol = defaultSelectedAlpnProtocol;
    }

    public Boolean getStopReceivingAfterFatal() {
        return stopReceivingAfterFatal;
    }

    public void setStopReceivingAfterFatal(Boolean stopReceivingAfterFatal) {
        this.stopReceivingAfterFatal = stopReceivingAfterFatal;
    }

    public Boolean getStopActionsAfterWarning() {
        return stopActionsAfterWarning;
    }

    public void setStopActionsAfterWarning(Boolean stopActionsAfterWarning) {
        this.stopActionsAfterWarning = stopActionsAfterWarning;
    }

    public Boolean getExpectHandshakeDoneQuicFrame() {
        return expectHandshakeDoneQuicFrame;
    }

    public void setExpectHandshakeDoneQuicFrame(Boolean expectHandshakeDoneQuicFrame) {
        this.expectHandshakeDoneQuicFrame = expectHandshakeDoneQuicFrame;
    }

    public QuicVersion getQuicVersion() {
        return quicVersion;
    }

    public void setQuicVersion(QuicVersion quicVersion) {
        this.quicVersion = quicVersion;
    }

    public Boolean isAcceptOnlyFittingDtlsFragments() {
        return acceptOnlyFittingDtlsFragments;
    }

    public void setAcceptOnlyFittingDtlsFragments(Boolean acceptOnlyFittingDtlsFragments) {
        this.acceptOnlyFittingDtlsFragments = acceptOnlyFittingDtlsFragments;
    }

    public Boolean isCanSkipMessageSequenceNumber() {
        return canSkipMessageSequenceNumber;
    }

    public void setCanSkipMessageSequenceNumber(Boolean canSkipMessageSequenceNumber) {
        this.canSkipMessageSequenceNumber = canSkipMessageSequenceNumber;
    }

    public Boolean isAcceptContentRewritingDtlsFragments() {
        return acceptContentRewritingDtlsFragments;
    }

    public void setAcceptContentRewritingDtlsFragments(
            Boolean acceptContentRewritingDtlsFragments) {
        this.acceptContentRewritingDtlsFragments = acceptContentRewritingDtlsFragments;
    }

    public Boolean getReorderReceivedDtlsRecords() {
        return reorderReceivedDtlsRecords;
    }

    public void setReorderReceivedDtlsRecords(Boolean reorderReceivedDtlsRecords) {
        this.reorderReceivedDtlsRecords = reorderReceivedDtlsRecords;
    }

    public Config createCopy() {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        ConfigIO.write(this, stream);
        return ConfigIO.read(new ByteArrayInputStream(stream.toByteArray()));
    }

    public CertificateType getDefaultSelectedServerCertificateType() {
        return defaultSelectedServerCertificateType;
    }

    public void setDefaultSelectedServerCertificateType(
            CertificateType defaultSelectedServerCertificateType) {
        this.defaultSelectedServerCertificateType = defaultSelectedServerCertificateType;
    }

    public CertificateType getDefaultSelectedClientCertificateType() {
        return defaultSelectedClientCertificateType;
    }

    public void setDefaultSelectedClientCertificateType(
            CertificateType defaultSelectedClientCertificateType) {
        this.defaultSelectedClientCertificateType = defaultSelectedClientCertificateType;
    }

    public ECPointFormat getDefaultSelectedPointFormat() {
        return defaultSelectedPointFormat;
    }

    public void setDefaultSelectedPointFormat(ECPointFormat defaultSelectedPointFormat) {
        this.defaultSelectedPointFormat = defaultSelectedPointFormat;
    }

    public Boolean getStopActionsAfterIOException() {
        return stopActionsAfterIOException;
    }

    public void setStopActionsAfterIOException(Boolean stopActionsAfterIOException) {
        this.stopActionsAfterIOException = stopActionsAfterIOException;
    }

    public Boolean getTls13BackwardsCompatibilityMode() {
        return tls13BackwardsCompatibilityMode;
    }

    public void setTls13BackwardsCompatibilityMode(Boolean tls13BackwardsCompatibilityMode) {
        this.tls13BackwardsCompatibilityMode = tls13BackwardsCompatibilityMode;
    }

    public Boolean isOverrideSessionIdForTickets() {
        return overrideSessionIdForTickets;
    }

    public void setOverrideSessionIdForTickets(Boolean overrideSessionIdForTickets) {
        this.overrideSessionIdForTickets = overrideSessionIdForTickets;
    }

    public long getSessionTicketLifetimeHint() {
        return sessionTicketLifetimeHint;
    }

    public void setSessionTicketLifetimeHint(long sessionTicketLifetimeHint) {
        this.sessionTicketLifetimeHint = sessionTicketLifetimeHint;
    }

    public byte[] getSessionTicketEncryptionKey() {
        return Arrays.copyOf(sessionTicketEncryptionKey, sessionTicketEncryptionKey.length);
    }

    public void setSessionTicketEncryptionKey(byte[] sessionTicketEncryptionKey) {
        this.sessionTicketEncryptionKey = sessionTicketEncryptionKey;
    }

    public byte[] getSessionTicketKeyHMAC() {
        return Arrays.copyOf(sessionTicketKeyHMAC, sessionTicketKeyHMAC.length);
    }

    public void setSessionTicketKeyHMAC(byte[] sessionTicketKeyHMAC) {
        this.sessionTicketKeyHMAC = sessionTicketKeyHMAC;
    }

    public byte[] getSessionTicketKeyName() {
        return Arrays.copyOf(sessionTicketKeyName, sessionTicketKeyName.length);
    }

    public void setSessionTicketKeyName(byte[] sessionTicketKeyName) {
        this.sessionTicketKeyName = sessionTicketKeyName;
    }

    public ClientAuthenticationType getClientAuthenticationType() {
        return clientAuthenticationType;
    }

    public void setClientAuthenticationType(ClientAuthenticationType clientAuthenticationType) {
        this.clientAuthenticationType = clientAuthenticationType;
    }

    public String getDefaultHttpsLocationPath() {
        return defaultHttpsLocationPath;
    }

    public void setDefaultHttpsLocationPath(String defaultHttpsLocationPath) {
        this.defaultHttpsLocationPath = defaultHttpsLocationPath;
    }

    public String getDefaultHttpsRequestPath() {
        return defaultHttpsRequestPath;
    }

    public void setDefaultHttpsRequestPath(String defaultHttpsRequestPath) {
        this.defaultHttpsRequestPath = defaultHttpsRequestPath;
    }

    public int getDefaultMaxHttpLength() {
        return defaultMaxHttpLength;
    }

    public void setDefaultMaxHttpLength(int defaultMaxHttpLength) {
        this.defaultMaxHttpLength = defaultMaxHttpLength;
    }

    public Boolean isUseFreshRandom() {
        return useFreshRandom;
    }

    public void setUseFreshRandom(Boolean useFreshRandom) {
        this.useFreshRandom = useFreshRandom;
    }

    public Boolean isUseAllProvidedDtlsFragments() {
        return useAllProvidedDtlsFragments;
    }

    public void setUseAllProvidedDtlsFragments(Boolean useAllProvidedDtlsFragments) {
        this.useAllProvidedDtlsFragments = useAllProvidedDtlsFragments;
    }

    public Boolean isUseAllProvidedRecords() {
        return useAllProvidedRecords;
    }

    public void setUseAllProvidedRecords(Boolean useAllProvidedRecords) {
        this.useAllProvidedRecords = useAllProvidedRecords;
    }

    public Boolean isUseAllProvidedQuicPackets() {
        return useAllProvidedQuicPackets;
    }

    public void setUseAllProvidedQuicPackets(Boolean useAllProvidedQuicPackets) {
        this.useAllProvidedQuicPackets = useAllProvidedQuicPackets;
    }

    public byte[] getDefaultServerRenegotiationInfo() {
        return Arrays.copyOf(defaultServerRenegotiationInfo, defaultServerRenegotiationInfo.length);
    }

    public void setDefaultServerRenegotiationInfo(byte[] defaultServerRenegotiationInfo) {
        this.defaultServerRenegotiationInfo = defaultServerRenegotiationInfo;
    }

    public ChooserType getChooserType() {
        return chooserType;
    }

    public void setChooserType(ChooserType chooserType) {
        this.chooserType = chooserType;
    }

    public Boolean isStealthMode() {
        return stealthMode;
    }

    public void setStealthMode(Boolean stealthMode) {
        this.stealthMode = stealthMode;
    }

    public BigInteger getDefaultServerDhExportGenerator() {
        return defaultServerEphemeralDhExportGenerator;
    }

    public void setDefaultServerDhExportGenerator(
            BigInteger defaultServerEphemeralDhExportGenerator) {
        this.defaultServerEphemeralDhExportGenerator = defaultServerEphemeralDhExportGenerator;
    }

    public BigInteger getDefaultServerDhExportModulus() {
        return defaultServerEphemeralDhExportModulus;
    }

    public void setDefaultServerDhExportModulus(BigInteger defaultServerEphemeralDhExportModulus) {
        if (defaultServerEphemeralDhExportModulus.signum() == 1) {
            this.defaultServerEphemeralDhExportModulus = defaultServerEphemeralDhExportModulus;
        } else {
            throw new IllegalArgumentException(
                    "Modulus cannot be negative or zero:"
                            + defaultServerEphemeralDhExportModulus.toString());
        }
    }

    public BigInteger getDefaultServerDhExportPublicKey() {
        return defaultServerEphemeralDhExportPublicKey;
    }

    public void setDefaultServerDhExportPublicKey(
            BigInteger defaultServerEphemeralDhExportPublicKey) {
        this.defaultServerEphemeralDhExportPublicKey = defaultServerEphemeralDhExportPublicKey;
    }

    public BigInteger getDefaultServerDhExportPrivateKey() {
        return defaultServerEphemeralDhExportPrivateKey;
    }

    public void setDefaultServerDhExportPrivateKey(
            BigInteger defaultServerEphemeralDhExportPrivateKey) {
        this.defaultServerEphemeralDhExportPrivateKey = defaultServerEphemeralDhExportPrivateKey;
    }

    public Point getDefaultTokenBindingECPublicKey() {
        return defaultTokenBindingECPublicKey;
    }

    public void setDefaultTokenBindingECPublicKey(Point defaultTokenBindingECPublicKey) {
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

    public byte[] getDefaultClientHandshakeTrafficSecret() {
        return Arrays.copyOf(
                defaultClientHandshakeTrafficSecret, defaultClientHandshakeTrafficSecret.length);
    }

    public void setDefaultClientHandshakeTrafficSecret(byte[] defaultClientHandshakeTrafficSecret) {
        this.defaultClientHandshakeTrafficSecret = defaultClientHandshakeTrafficSecret;
    }

    public byte[] getDefaultServerHandshakeTrafficSecret() {
        return Arrays.copyOf(
                defaultServerHandshakeTrafficSecret, defaultServerHandshakeTrafficSecret.length);
    }

    public void setDefaultServerHandshakeTrafficSecret(byte[] defaultServerHandshakeTrafficSecret) {
        this.defaultServerHandshakeTrafficSecret = defaultServerHandshakeTrafficSecret;
    }

    public byte[] getDefaultCertificateRequestContext() {
        return Arrays.copyOf(
                defaultCertificateRequestContext, defaultCertificateRequestContext.length);
    }

    public void setDefaultCertificateRequestContext(byte[] defaultCertificateRequestContext) {
        this.defaultCertificateRequestContext = defaultCertificateRequestContext;
    }

    public Boolean isWorkflowExecutorShouldOpen() {
        return workflowExecutorShouldOpen;
    }

    public void setWorkflowExecutorShouldOpen(Boolean workflowExecutorShouldOpen) {
        this.workflowExecutorShouldOpen = workflowExecutorShouldOpen;
    }

    public Boolean isWorkflowExecutorShouldClose() {
        return workflowExecutorShouldClose;
    }

    public void setWorkflowExecutorShouldClose(Boolean workflowExecutorShouldClose) {
        this.workflowExecutorShouldClose = workflowExecutorShouldClose;
    }

    public byte[] getDefaultPSKKey() {
        return Arrays.copyOf(defaultPSKKey, defaultPSKKey.length);
    }

    public void setDefaultPSKKey(byte[] defaultPSKKey) {
        this.defaultPSKKey = defaultPSKKey;
    }

    public byte[] getDefaultPSKIdentity() {
        return Arrays.copyOf(defaultPSKIdentity, defaultPSKIdentity.length);
    }

    public void setDefaultPSKIdentity(byte[] defaultPSKIdentity) {
        this.defaultPSKIdentity = defaultPSKIdentity;
    }

    public byte[] getDefaultPSKIdentityHint() {
        return Arrays.copyOf(defaultPSKIdentityHint, defaultPSKIdentityHint.length);
    }

    public void setDefaultPSKIdentityHint(byte[] defaultPSKIdentityHint) {
        this.defaultPSKIdentityHint = defaultPSKIdentityHint;
    }

    public BigInteger getDefaultSRPModulus() {
        return defaultSRPModulus;
    }

    public void setDefaultSRPModulus(BigInteger defaultSRPModulus) {
        this.defaultSRPModulus = defaultSRPModulus;
    }

    public BigInteger getDefaultSRPServerPrivateKey() {
        return defaultSRPServerPrivateKey;
    }

    public void setDefaultSRPServerPrivateKey(BigInteger defaultSRPServerPrivateKey) {
        this.defaultSRPServerPrivateKey = defaultSRPServerPrivateKey;
    }

    public BigInteger getDefaultSRPServerPublicKey() {
        return defaultSRPServerPublicKey;
    }

    public void setDefaultSRPServerPublicKey(BigInteger defaultSRPServerPublicKey) {
        this.defaultSRPServerPublicKey = defaultSRPServerPublicKey;
    }

    public BigInteger getDefaultSRPClientPrivateKey() {
        return defaultSRPClientPrivateKey;
    }

    public void setDefaultSRPClientPrivateKey(BigInteger defaultSRPClientPrivateKey) {
        this.defaultSRPClientPrivateKey = defaultSRPClientPrivateKey;
    }

    public BigInteger getDefaultSRPClientPublicKey() {
        return defaultSRPClientPublicKey;
    }

    public void setDefaultSRPClientPublicKey(BigInteger defaultSRPClientPublicKey) {
        this.defaultSRPClientPublicKey = defaultSRPClientPublicKey;
    }

    public BigInteger getDefaultSRPGenerator() {
        return defaultSRPGenerator;
    }

    public void setDefaultSRPGenerator(BigInteger defaultSRPGenerator) {
        this.defaultSRPGenerator = defaultSRPGenerator;
    }

    public byte[] getDefaultSRPServerSalt() {
        return Arrays.copyOf(defaultSRPServerSalt, defaultSRPServerSalt.length);
    }

    public void setDefaultSRPServerSalt(byte[] defaultSRPServerSalt) {
        this.defaultSRPServerSalt = defaultSRPServerSalt;
    }

    public byte[] getDefaultSRPIdentity() {
        return Arrays.copyOf(defaultSRPIdentity, defaultSRPIdentity.length);
    }

    public void setDefaultSRPIdentity(byte[] defaultSRPIdentity) {
        this.defaultSRPIdentity = defaultSRPIdentity;
    }

    public byte[] getDefaultSRPPassword() {
        return Arrays.copyOf(defaultSRPPassword, defaultSRPPassword.length);
    }

    public void setDefaultSRPPassword(byte[] defaultSRPPassword) {
        this.defaultSRPPassword = defaultSRPPassword;
    }

    public AlertDescription getDefaultAlertDescription() {
        return defaultAlertDescription;
    }

    public void setDefaultAlertDescription(AlertDescription defaultAlertDescription) {
        this.defaultAlertDescription = defaultAlertDescription;
    }

    public AlertLevel getDefaultAlertLevel() {
        return defaultAlertLevel;
    }

    public void setDefaultAlertLevel(AlertLevel defaultAlertLevel) {
        this.defaultAlertLevel = defaultAlertLevel;
    }

    public GOSTCurve getDefaultSelectedGostCurve() {
        return defaultSelectedGostCurve;
    }

    public void setDefaultSelectedGostCurve(GOSTCurve defaultSelectedGostCurve) {
        this.defaultSelectedGostCurve = defaultSelectedGostCurve;
    }

    public PRFAlgorithm getDefaultPRFAlgorithm() {
        return defaultPRFAlgorithm;
    }

    public void setDefaultPRFAlgorithm(PRFAlgorithm defaultPRFAlgorithm) {
        this.defaultPRFAlgorithm = defaultPRFAlgorithm;
    }

    public byte[] getDtlsDefaultCookie() {
        return Arrays.copyOf(dtlsDefaultCookie, dtlsDefaultCookie.length);
    }

    public void setDtlsDefaultCookie(byte[] defaultDtlsCookie) {
        this.dtlsDefaultCookie = defaultDtlsCookie;
    }

    public Integer getDtlsDefaultCookieLength() {
        return dtlsDefaultCookieLength;
    }

    public void setDtlsDefaultCookieLength(Integer dtlsDefaultCookieLength) {
        this.dtlsDefaultCookieLength = dtlsDefaultCookieLength;
    }

    public Integer getDtlsMaximumFragmentLength() {
        return dtlsMaximumFragmentLength;
    }

    public void setDtlsMaximumFragmentLength(Integer dtlsMaximumFragmentLength) {
        this.dtlsMaximumFragmentLength = dtlsMaximumFragmentLength;
    }

    public Integer getQuicMaximumFrameSize() {
        return quicMaximumFrameSize;
    }

    public void setQuicMaximumFrameSize(Integer quicMaximumFrameSize) {
        this.quicMaximumFrameSize = quicMaximumFrameSize;
    }

    public byte[] getDefaultClientSessionId() {
        return Arrays.copyOf(defaultClientSessionId, defaultClientSessionId.length);
    }

    public void setDefaultClientSessionId(byte[] defaultClientSessionId) {
        this.defaultClientSessionId = defaultClientSessionId;
    }

    public byte[] getDefaultServerSessionId() {
        return Arrays.copyOf(defaultServerSessionId, defaultServerSessionId.length);
    }

    public void setDefaultServerSessionId(byte[] defaultServerSessionId) {
        this.defaultServerSessionId = defaultServerSessionId;
    }

    public CompressionMethod getDefaultSelectedCompressionMethod() {
        return defaultSelectedCompressionMethod;
    }

    public void setDefaultSelectedCompressionMethod(
            CompressionMethod defaultSelectedCompressionMethod) {
        this.defaultSelectedCompressionMethod = defaultSelectedCompressionMethod;
    }

    public Boolean isAddQuicTransportParametersExtension() {
        return this.addQuicTransportParametersExtension;
    }

    public void setQuicTransportParametersExtension(Boolean addQuicTransportParameterExtension) {
        this.addQuicTransportParametersExtension = addQuicTransportParameterExtension;
    }

    public Boolean isAddExtendedRandomExtension() {
        return this.addExtendedRandomExtension;
    }

    public void setAddExtendedRandomExtension(Boolean addExtendedRandomExtension) {
        this.addExtendedRandomExtension = addExtendedRandomExtension;
    }

    public byte[] getDefaultClientExtendedRandom() {
        return Arrays.copyOf(defaultClientExtendedRandom, defaultClientExtendedRandom.length);
    }

    public byte[] getDefaultServerExtendedRandom() {
        return Arrays.copyOf(defaultServerExtendedRandom, defaultServerExtendedRandom.length);
    }

    public void setDefaultClientExtendedRandom(byte[] defaultClientExtendedRandom) {
        this.defaultClientExtendedRandom = defaultClientExtendedRandom;
    }

    public void setDefaultServerExtendedRandom(byte[] defaultServerExtendedRandom) {
        this.defaultServerExtendedRandom = defaultServerExtendedRandom;
    }

    public byte[] getDefaultServerRandom() {
        return Arrays.copyOf(defaultServerRandom, defaultServerRandom.length);
    }

    public void setDefaultServerRandom(byte[] defaultServerRandom) {
        this.defaultServerRandom = defaultServerRandom;
    }

    public byte[] getDefaultClientRandom() {
        return Arrays.copyOf(defaultClientRandom, defaultClientRandom.length);
    }

    public void setDefaultClientRandom(byte[] defaultClientRandom) {
        this.defaultClientRandom = defaultClientRandom;
    }

    public byte[] getDefaultPreMasterSecret() {
        return Arrays.copyOf(defaultPreMasterSecret, defaultPreMasterSecret.length);
    }

    public void setDefaultPreMasterSecret(byte[] defaultPreMasterSecret) {
        this.defaultPreMasterSecret = defaultPreMasterSecret;
    }

    public byte[] getDefaultMasterSecret() {
        return Arrays.copyOf(defaultMasterSecret, defaultMasterSecret.length);
    }

    public void setDefaultMasterSecret(byte[] defaultMasterSecret) {
        this.defaultMasterSecret = defaultMasterSecret;
    }

    public ProtocolVersion getDefaultHighestClientProtocolVersion() {
        return defaultHighestClientProtocolVersion;
    }

    public void setDefaultHighestClientProtocolVersion(
            ProtocolVersion defaultHighestClientProtocolVersion) {
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
        this.defaultServerSupportedSignatureAndHashAlgorithms =
                defaultServerSupportedSignatureAndHashAlgorithms;
    }

    public void setDefaultServerSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm... defaultServerSupportedSignatureAndHashAlgorithms) {
        this.defaultServerSupportedSignatureAndHashAlgorithms =
                new ArrayList<>(Arrays.asList(defaultServerSupportedSignatureAndHashAlgorithms));
    }

    public List<SignatureAndHashAlgorithm> getDefaultServerSupportedCertificateSignAlgorithms() {
        return defaultServerSupportedCertificateSignAlgorithms;
    }

    public void setDefaultServerSupportedCertificateSignAlgorithms(
            List<SignatureAndHashAlgorithm> defaultServerSupportedCertificateSignAlgorithms) {
        this.defaultServerSupportedCertificateSignAlgorithms =
                defaultServerSupportedCertificateSignAlgorithms;
    }

    public void setDefaultServerSupportedCertificateSignAlgorithms(
            SignatureAndHashAlgorithm... defaultServerSupportedCertificateSignAlgorithms) {
        this.defaultServerSupportedCertificateSignAlgorithms =
                new ArrayList<>(Arrays.asList(defaultServerSupportedCertificateSignAlgorithms));
    }

    public List<CipherSuite> getDefaultServerSupportedCipherSuites() {
        return defaultServerSupportedCipherSuites;
    }

    public void setDefaultServerSupportedCipherSuites(
            List<CipherSuite> defaultServerSupportedCipherSuites) {
        this.defaultServerSupportedCipherSuites = defaultServerSupportedCipherSuites;
    }

    public final void setDefaultServerSupportedCipherSuites(
            CipherSuite... defaultServerSupportedCipherSuites) {
        this.defaultServerSupportedCipherSuites =
                new ArrayList<>(Arrays.asList(defaultServerSupportedCipherSuites));
    }

    public List<CompressionMethod> getDefaultClientSupportedCompressionMethods() {
        return defaultClientSupportedCompressionMethods;
    }

    public void setDefaultClientSupportedCompressionMethods(
            List<CompressionMethod> defaultClientSupportedCompressionMethods) {
        this.defaultClientSupportedCompressionMethods = defaultClientSupportedCompressionMethods;
    }

    public final void setDefaultClientSupportedCompressionMethods(
            CompressionMethod... defaultClientSupportedCompressionMethods) {
        this.defaultClientSupportedCompressionMethods =
                new ArrayList<>(Arrays.asList(defaultClientSupportedCompressionMethods));
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

    public Integer getInboundRecordSizeLimit() {
        return inboundRecordSizeLimit;
    }

    public void setInboundRecordSizeLimit(Integer inboundRecordSizeLimit) {
        this.inboundRecordSizeLimit = inboundRecordSizeLimit;
    }

    public SignatureAndHashAlgorithm getDefaultSelectedSignatureAndHashAlgorithm() {
        return defaultSelectedSignatureAndHashAlgorithm;
    }

    public void setDefaultSelectedSignatureAndHashAlgorithm(
            SignatureAndHashAlgorithm defaultSelectedSignatureAndHashAlgorithm) {
        this.defaultSelectedSignatureAndHashAlgorithm = defaultSelectedSignatureAndHashAlgorithm;
    }

    public SignatureAndHashAlgorithm getDefaultSelectedSignatureAlgorithmCert() {
        return defaultSelectedSignatureAlgorithmCert;
    }

    public void setDefaultSelectedSignatureAlgorithmCert(
            SignatureAndHashAlgorithm defaultSelectedSignatureAlgorithmCert) {
        this.defaultSelectedSignatureAlgorithmCert = defaultSelectedSignatureAlgorithmCert;
    }

    public List<ECPointFormat> getDefaultClientSupportedPointFormats() {
        return defaultClientSupportedPointFormats;
    }

    public void setDefaultClientSupportedPointFormats(
            List<ECPointFormat> defaultClientSupportedPointFormats) {
        this.defaultClientSupportedPointFormats = defaultClientSupportedPointFormats;
    }

    public final void setDefaultClientSupportedPointFormats(
            ECPointFormat... defaultClientSupportedPointFormats) {
        this.defaultClientSupportedPointFormats =
                new ArrayList<>(Arrays.asList(defaultClientSupportedPointFormats));
    }

    public ProtocolVersion getDefaultLastRecordProtocolVersion() {
        return defaultLastRecordProtocolVersion;
    }

    public void setDefaultLastRecordProtocolVersion(
            ProtocolVersion defaultLastRecordProtocolVersion) {
        this.defaultLastRecordProtocolVersion = defaultLastRecordProtocolVersion;
    }

    public List<ECPointFormat> getDefaultServerSupportedPointFormats() {
        return defaultServerSupportedPointFormats;
    }

    public void setDefaultServerSupportedPointFormats(
            List<ECPointFormat> defaultServerSupportedPointFormats) {
        this.defaultServerSupportedPointFormats = defaultServerSupportedPointFormats;
    }

    public final void setDefaultServerSupportedPointFormats(
            ECPointFormat... defaultServerSupportedPointFormats) {
        this.defaultServerSupportedPointFormats =
                new ArrayList<>(Arrays.asList(defaultServerSupportedPointFormats));
    }

    public List<NamedGroup> getDefaultClientNamedGroups() {
        return defaultClientNamedGroups;
    }

    public void setDefaultClientNamedGroups(List<NamedGroup> defaultClientNamedGroups) {
        this.defaultClientNamedGroups = defaultClientNamedGroups;
    }

    public final void setDefaultClientNamedGroups(NamedGroup... defaultClientNamedGroups) {
        this.defaultClientNamedGroups = new ArrayList<>(Arrays.asList(defaultClientNamedGroups));
    }

    public List<NamedGroup> getDefaultServerNamedGroups() {
        return defaultServerNamedGroups;
    }

    public void setDefaultServerNamedGroups(List<NamedGroup> defaultServerNamedGroups) {
        this.defaultServerNamedGroups = defaultServerNamedGroups;
    }

    public final void setDefaultServerNamedGroups(NamedGroup... defaultServerNamedGroups) {
        this.defaultServerNamedGroups = new ArrayList<>(Arrays.asList(defaultServerNamedGroups));
    }

    public CipherSuite getDefaultSelectedCipherSuite() {
        return defaultSelectedCipherSuite;
    }

    public void setDefaultSelectedCipherSuite(CipherSuite defaultSelectedCipherSuite) {
        this.defaultSelectedCipherSuite = defaultSelectedCipherSuite;
    }

    public SSL2CipherSuite getDefaultSSL2CipherSuite() {
        return defaultSSL2CipherSuite;
    }

    public void setDefaultSSL2CipherSuite(SSL2CipherSuite defaultSSL2CipherSuite) {
        this.defaultSSL2CipherSuite = defaultSSL2CipherSuite;
    }

    public Integer getReceiveMaximumBytes() {
        return receiveMaximumBytes;
    }

    public void setReceiveMaximumBytes(int receiveMaximumBytes) {
        this.receiveMaximumBytes = receiveMaximumBytes;
    }

    public Boolean isResetWorkflowTracesBeforeSaving() {
        return resetWorkflowTracesBeforeSaving;
    }

    public void setResetWorkflowTracesBeforeSaving(Boolean resetWorkflowTracesBeforeSaving) {
        this.resetWorkflowTracesBeforeSaving = resetWorkflowTracesBeforeSaving;
    }

    public Boolean isFlushOnMessageTypeChange() {
        return flushOnMessageTypeChange;
    }

    public void setFlushOnMessageTypeChange(Boolean flushOnMessageTypeChange) {
        this.flushOnMessageTypeChange = flushOnMessageTypeChange;
    }

    public Boolean isCreateFragmentsDynamically() {
        return createFragmentsDynamically;
    }

    public void setCreateFragmentsDynamically(Boolean createFragmentsDynamically) {
        this.createFragmentsDynamically = createFragmentsDynamically;
    }

    public Boolean isCreateRecordsDynamically() {
        return createRecordsDynamically;
    }

    public void setCreateRecordsDynamically(Boolean createRecordsDynamically) {
        this.createRecordsDynamically = createRecordsDynamically;
    }

    public Boolean isIndividualTransportPacketsForFragments() {
        return individualTransportPacketsForFragments;
    }

    public void setIndividualTransportPacketsForFragments(
            Boolean individualTransportPacketsForFragments) {
        this.individualTransportPacketsForFragments = individualTransportPacketsForFragments;
    }

    public Integer getIndividualTransportPacketCooldown() {
        return individualTransportPacketCooldown;
    }

    public void setIndividualTransportPacketCooldown(Integer individualTransportPacketCooldown) {
        this.individualTransportPacketCooldown = individualTransportPacketCooldown;
    }

    public Integer getDefaultMaxRecordData() {
        return defaultMaxRecordData;
    }

    public void setDefaultMaxRecordData(int defaultMaxRecordData) {
        if (defaultMaxRecordData == 0) {
            LOGGER.warn("defaultMaxRecordData is being set to 0");
        }
        this.defaultMaxRecordData = defaultMaxRecordData;
    }

    public WorkflowExecutorType getWorkflowExecutorType() {
        return workflowExecutorType;
    }

    public void setWorkflowExecutorType(WorkflowExecutorType workflowExecutorType) {
        this.workflowExecutorType = workflowExecutorType;
    }

    public SniType getSniType() {
        return sniType;
    }

    public void setSniType(SniType sniType) {
        this.sniType = sniType;
    }

    public Integer getHeartbeatPayloadLength() {
        return heartbeatPayloadLength;
    }

    public void setHeartbeatPayloadLength(int heartbeatPayloadLength) {
        this.heartbeatPayloadLength = heartbeatPayloadLength;
    }

    public Integer getHeartbeatPaddingLength() {
        return heartbeatPaddingLength;
    }

    public void setHeartbeatPaddingLength(int heartbeatPaddingLength) {
        this.heartbeatPaddingLength = heartbeatPaddingLength;
    }

    public Boolean isAddPaddingExtension() {
        return addPaddingExtension;
    }

    public void setAddPaddingExtension(Boolean addPaddingExtension) {
        this.addPaddingExtension = addPaddingExtension;
    }

    public Boolean isAddExtendedMasterSecretExtension() {
        return addExtendedMasterSecretExtension;
    }

    public void setAddExtendedMasterSecretExtension(Boolean addExtendedMasterSecretExtension) {
        this.addExtendedMasterSecretExtension = addExtendedMasterSecretExtension;
    }

    public Boolean isAddSessionTicketTLSExtension() {
        return addSessionTicketTLSExtension;
    }

    public void setAddSessionTicketTLSExtension(Boolean addSessionTicketTLSExtension) {
        this.addSessionTicketTLSExtension = addSessionTicketTLSExtension;
    }

    public byte[] getDefaultPaddingExtensionBytes() {
        return Arrays.copyOf(defaultPaddingExtensionBytes, defaultPaddingExtensionBytes.length);
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

    public final void setClientCertificateTypes(ClientCertificateType... clientCertificateTypes) {
        this.clientCertificateTypes = new ArrayList<>(Arrays.asList(clientCertificateTypes));
    }

    public String getDefaultApplicationMessageData() {
        return defaultApplicationMessageData;
    }

    public void setDefaultApplicationMessageData(String defaultApplicationMessageData) {
        this.defaultApplicationMessageData = defaultApplicationMessageData;
    }

    public Boolean isEnforceSettings() {
        return enforceSettings;
    }

    public void setEnforceSettings(Boolean enforceSettings) {
        this.enforceSettings = enforceSettings;
    }

    public byte[] getDistinguishedNames() {
        return Arrays.copyOf(distinguishedNames, distinguishedNames.length);
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

    public Boolean isServerSendsApplicationData() {
        return serverSendsApplicationData;
    }

    public void setServerSendsApplicationData(Boolean serverSendsApplicationData) {
        this.serverSendsApplicationData = serverSendsApplicationData;
    }

    public WorkflowTraceType getWorkflowTraceType() {
        return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
        this.workflowTraceType = workflowTraceType;
    }

    public NamedGroup getDefaultSelectedNamedGroup() {
        return defaultSelectedNamedGroup;
    }

    public void setDefaultSelectedNamedGroup(NamedGroup defaultSelectedNamedGroup) {
        this.defaultSelectedNamedGroup = defaultSelectedNamedGroup;
    }

    public Boolean isDynamicWorkflow() {
        throw new UnsupportedOperationException("DynamicWorkflow is currently not supported.");
    }

    public void setDynamicWorkflow(Boolean dynamicWorkflow) {
        throw new UnsupportedOperationException("DynamicWorkflow is currently not supported.");
    }

    public List<CipherSuite> getDefaultClientSupportedCipherSuites() {
        return defaultClientSupportedCipherSuites;
    }

    public void setDefaultClientSupportedCipherSuites(
            List<CipherSuite> defaultClientSupportedCipherSuites) {
        this.defaultClientSupportedCipherSuites = defaultClientSupportedCipherSuites;
    }

    public final void setDefaultClientSupportedCipherSuites(
            CipherSuite... defaultClientSupportedCipherSuites) {
        this.defaultClientSupportedCipherSuites =
                new ArrayList<>(Arrays.asList(defaultClientSupportedCipherSuites));
    }

    public Boolean isDtlsCookieExchange() {
        return dtlsCookieExchange;
    }

    public void setDtlsCookieExchange(Boolean dtlsCookieExchange) {
        this.dtlsCookieExchange = dtlsCookieExchange;
    }

    public Boolean isClientAuthentication() {
        return clientAuthentication;
    }

    public void setClientAuthentication(Boolean clientAuthentication) {
        this.clientAuthentication = clientAuthentication;
    }

    public List<SignatureAndHashAlgorithm> getDefaultClientSupportedSignatureAndHashAlgorithms() {
        return defaultClientSupportedSignatureAndHashAlgorithms;
    }

    public void setDefaultClientSupportedSignatureAndHashAlgorithms(
            List<SignatureAndHashAlgorithm> defaultClientSupportedSignatureAndHashAlgorithms) {
        this.defaultClientSupportedSignatureAndHashAlgorithms =
                defaultClientSupportedSignatureAndHashAlgorithms;
    }

    public final void setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm... supportedSignatureAndHashAlgorithms) {
        this.defaultClientSupportedSignatureAndHashAlgorithms =
                new ArrayList<>(Arrays.asList(supportedSignatureAndHashAlgorithms));
    }

    public List<SignatureAndHashAlgorithm> getDefaultClientSupportedCertificateSignAlgorithms() {
        return defaultClientSupportedCertificateSignAlgorithms;
    }

    public void setDefaultClientSupportedCertificateSignAlgorithms(
            List<SignatureAndHashAlgorithm> defaultClientSupportedCertificateSignAlgorithms) {
        this.defaultClientSupportedCertificateSignAlgorithms =
                defaultClientSupportedCertificateSignAlgorithms;
    }

    public final void setDefaultClientSupportedCertificateSignAlgorithms(
            SignatureAndHashAlgorithm... supportedSignatureAndHashAlgorithms) {
        this.defaultClientSupportedCertificateSignAlgorithms =
                new ArrayList<>(Arrays.asList(supportedSignatureAndHashAlgorithms));
    }

    public List<ProtocolVersion> getSupportedVersions() {
        return supportedVersions;
    }

    public void setSupportedVersions(List<ProtocolVersion> supportedVersions) {
        this.supportedVersions = supportedVersions;
    }

    public final void setSupportedVersions(ProtocolVersion... supportedVersions) {
        this.supportedVersions = new ArrayList<>(Arrays.asList(supportedVersions));
    }

    public HeartbeatMode getHeartbeatMode() {
        return heartbeatMode;
    }

    public void setHeartbeatMode(HeartbeatMode heartbeatMode) {
        this.heartbeatMode = heartbeatMode;
    }

    public Boolean isAddECPointFormatExtension() {
        return addECPointFormatExtension;
    }

    public void setAddECPointFormatExtension(Boolean addECPointFormatExtension) {
        this.addECPointFormatExtension = addECPointFormatExtension;
    }

    public Boolean isAddExtensionsInSSL() {
        return addExtensionsInSSL;
    }

    public void setAddExtensionsInSSL(Boolean addExtensionsInSSL) {
        this.addExtensionsInSSL = addExtensionsInSSL;
    }

    public Boolean isAddEllipticCurveExtension() {
        return addEllipticCurveExtension;
    }

    public void setAddEllipticCurveExtension(Boolean addEllipticCurveExtension) {
        this.addEllipticCurveExtension = addEllipticCurveExtension;
    }

    public Boolean isAddHeartbeatExtension() {
        return addHeartbeatExtension;
    }

    public void setAddHeartbeatExtension(Boolean addHeartbeatExtension) {
        this.addHeartbeatExtension = addHeartbeatExtension;
    }

    public Boolean isAddMaxFragmentLengthExtension() {
        return addMaxFragmentLengthExtension;
    }

    public void setAddMaxFragmentLengthExtension(Boolean addMaxFragmentLengthExtension) {
        this.addMaxFragmentLengthExtension = addMaxFragmentLengthExtension;
    }

    public Boolean isAddRecordSizeLimitExtension() {
        return addRecordSizeLimitExtension;
    }

    public void setAddRecordSizeLimitExtension(Boolean addRecordSizeLimitExtension) {
        this.addRecordSizeLimitExtension = addRecordSizeLimitExtension;
    }

    public Boolean isAddServerNameIndicationExtension() {
        return addServerNameIndicationExtension;
    }

    public void setAddServerNameIndicationExtension(Boolean addServerNameIndicationExtension) {
        this.addServerNameIndicationExtension = addServerNameIndicationExtension;
    }

    public Boolean isAddSignatureAndHashAlgorithmsExtension() {
        return addSignatureAndHashAlgorithmsExtension;
    }

    public void setAddSignatureAndHashAlgorithmsExtension(
            Boolean addSignatureAndHashAlgorithmsExtension) {
        this.addSignatureAndHashAlgorithmsExtension = addSignatureAndHashAlgorithmsExtension;
    }

    public Boolean isAddSignatureAlgorithmsCertExtension() {
        return addSignatureAlgorithmsCertExtension;
    }

    public void setAddSignatureAlgorithmsCertExtension(
            Boolean addSignatureAlgorithmsCertExtension) {
        this.addSignatureAlgorithmsCertExtension = addSignatureAlgorithmsCertExtension;
    }

    public Boolean isAddSupportedVersionsExtension() {
        return addSupportedVersionsExtension;
    }

    public void setAddSupportedVersionsExtension(Boolean addSupportedVersionsExtension) {
        this.addSupportedVersionsExtension = addSupportedVersionsExtension;
    }

    public Boolean isAddKeyShareExtension() {
        return addKeyShareExtension;
    }

    public void setAddKeyShareExtension(Boolean addKeyShareExtension) {
        this.addKeyShareExtension = addKeyShareExtension;
    }

    public Boolean isAddEarlyDataExtension() {
        return addEarlyDataExtension;
    }

    public Boolean isAddDebugExtension() {
        return addDebugExtension;
    }

    public void setAddEarlyDataExtension(Boolean addEarlyDataExtension) {
        this.addEarlyDataExtension = addEarlyDataExtension;
    }

    public void setAddDebugExtension(Boolean addDebugExtension) {
        this.addDebugExtension = addDebugExtension;
    }

    public Boolean isAddEncryptedServerNameIndicationExtension() {
        return addEncryptedServerNameIndicationExtension;
    }

    public void setAddEncryptedServerNameIndicationExtension(
            Boolean addEncryptedServerNameIndicationExtension) {
        this.addEncryptedServerNameIndicationExtension = addEncryptedServerNameIndicationExtension;
    }

    public Boolean isAddEncryptedClientHelloExtension() {
        return addEncryptedClientHelloExtension;
    }

    public void setAddEncryptedClientHelloExtension(Boolean addEncryptedClientHelloExtension) {
        this.addEncryptedClientHelloExtension = addEncryptedClientHelloExtension;
    }

    public void setAddPWDClearExtension(Boolean addPWDClearExtension) {
        this.addPWDClearExtension = addPWDClearExtension;
    }

    public Boolean isAddPSKKeyExchangeModesExtension() {
        return addPSKKeyExchangeModesExtension;
    }

    public void setAddPSKKeyExchangeModesExtension(Boolean addPSKKeyExchangeModesExtension) {
        this.addPSKKeyExchangeModesExtension = addPSKKeyExchangeModesExtension;
    }

    public Boolean isAddPreSharedKeyExtension() {
        return addPreSharedKeyExtension;
    }

    public Boolean isAddPWDClearExtension() {
        return addPWDClearExtension;
    }

    public void setAddPreSharedKeyExtension(Boolean addPreSharedKeyExtension) {
        this.addPreSharedKeyExtension = addPreSharedKeyExtension;
    }

    public void setPSKKeyExchangeModes(List<PskKeyExchangeMode> pskKeyExchangeModes) {
        this.pskKeyExchangeModes = pskKeyExchangeModes;
    }

    public List<PskKeyExchangeMode> getPSKKeyExchangeModes() {
        return pskKeyExchangeModes;
    }

    public Integer getDefaultAdditionalPadding() {
        return defaultAdditionalPadding;
    }

    public void setDefaultAdditionalPadding(Integer defaultAdditionalPadding) {
        this.defaultAdditionalPadding = defaultAdditionalPadding;
    }

    public byte[] getTlsSessionTicket() {
        return Arrays.copyOf(tlsSessionTicket, tlsSessionTicket.length);
    }

    public void setTlsSessionTicket(byte[] tlsSessionTicket) {
        this.tlsSessionTicket = tlsSessionTicket;
    }

    public byte[] getDefaultSignedCertificateTimestamp() {
        return Arrays.copyOf(
                defaultSignedCertificateTimestamp, defaultSignedCertificateTimestamp.length);
    }

    public void setDefaultSignedCertificateTimestamp(byte[] defaultSignedCertificateTimestamp) {
        this.defaultSignedCertificateTimestamp = defaultSignedCertificateTimestamp;
    }

    public Boolean isAddSignedCertificateTimestampExtension() {
        return addSignedCertificateTimestampExtension;
    }

    public void setAddSignedCertificateTimestampExtension(
            Boolean addSignedCertificateTimestampExtension) {
        this.addSignedCertificateTimestampExtension = addSignedCertificateTimestampExtension;
    }

    public byte[] getDefaultClientRenegotiationInfo() {
        return Arrays.copyOf(defaultClientRenegotiationInfo, defaultClientRenegotiationInfo.length);
    }

    public void setDefaultClientRenegotiationInfo(byte[] defaultClientRenegotiationInfo) {
        this.defaultClientRenegotiationInfo = defaultClientRenegotiationInfo;
    }

    public Boolean isAddRenegotiationInfoExtension() {
        return addRenegotiationInfoExtension;
    }

    public void setAddRenegotiationInfoExtension(Boolean addRenegotiationInfoExtension) {
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

    public void setDefaultTokenBindingKeyParameters(
            List<TokenBindingKeyParameters> defaultTokenBindingKeyParameters) {
        this.defaultTokenBindingKeyParameters = defaultTokenBindingKeyParameters;
    }

    public final void setDefaultTokenBindingKeyParameters(
            TokenBindingKeyParameters... defaultTokenBindingKeyParameters) {
        this.defaultTokenBindingKeyParameters =
                new ArrayList<>(Arrays.asList(defaultTokenBindingKeyParameters));
    }

    public Boolean isAddTokenBindingExtension() {
        return addTokenBindingExtension;
    }

    public void setAddTokenBindingExtension(Boolean addTokenBindingExtension) {
        this.addTokenBindingExtension = addTokenBindingExtension;
    }

    public Boolean isAddHttpCookie() {
        return addHttpCookie;
    }

    public void setAddHttpCookie(Boolean addHttpCookie) {
        this.addHttpCookie = addHttpCookie;
    }

    public String getDefaultHttpCookieName() {
        return defaultHttpCookieName;
    }

    public void setDefaultHttpCookieName(String defaultHttpCookieName) {
        this.defaultHttpCookieName = defaultHttpCookieName;
    }

    public String getDefaultHttpCookieValue() {
        return defaultHttpCookieValue;
    }

    public void setDefaultHttpCookieValue(String defaultHttpCookieValue) {
        this.defaultHttpCookieValue = defaultHttpCookieValue;
    }

    public CertificateStatusRequestType getCertificateStatusRequestExtensionRequestType() {
        return certificateStatusRequestExtensionRequestType;
    }

    public void setCertificateStatusRequestExtensionRequestType(
            CertificateStatusRequestType certificateStatusRequestExtensionRequestType) {
        this.certificateStatusRequestExtensionRequestType =
                certificateStatusRequestExtensionRequestType;
    }

    public byte[] getCertificateStatusRequestExtensionResponderIDList() {
        return Arrays.copyOf(
                certificateStatusRequestExtensionResponderIDList,
                certificateStatusRequestExtensionResponderIDList.length);
    }

    public void setCertificateStatusRequestExtensionResponderIDList(
            byte[] certificateStatusRequestExtensionResponderIDList) {
        this.certificateStatusRequestExtensionResponderIDList =
                certificateStatusRequestExtensionResponderIDList;
    }

    public byte[] getCertificateStatusRequestExtensionRequestExtension() {
        return Arrays.copyOf(
                certificateStatusRequestExtensionRequestExtension,
                certificateStatusRequestExtensionRequestExtension.length);
    }

    public void setCertificateStatusRequestExtensionRequestExtension(
            byte[] certificateStatusRequestExtensionRequestExtension) {
        this.certificateStatusRequestExtensionRequestExtension =
                certificateStatusRequestExtensionRequestExtension;
    }

    public byte[] getSecureRemotePasswordExtensionIdentifier() {
        return Arrays.copyOf(
                secureRemotePasswordExtensionIdentifier,
                secureRemotePasswordExtensionIdentifier.length);
    }

    public void setSecureRemotePasswordExtensionIdentifier(
            byte[] secureRemotePasswordExtensionIdentifier) {
        this.secureRemotePasswordExtensionIdentifier = secureRemotePasswordExtensionIdentifier;
    }

    public List<SrtpProtectionProfile> getClientSupportedSrtpProtectionProfiles() {
        return clientSupportedSrtpProtectionProfiles;
    }

    public void setClientSupportedSrtpProtectionProfiles(
            List<SrtpProtectionProfile> secureRealTimeTransportProtocolProtectionProfiles) {
        this.clientSupportedSrtpProtectionProfiles =
                secureRealTimeTransportProtocolProtectionProfiles;
    }

    public byte[] getSecureRealTimeTransportProtocolMasterKeyIdentifier() {
        return Arrays.copyOf(
                secureRealTimeTransportProtocolMasterKeyIdentifier,
                secureRealTimeTransportProtocolMasterKeyIdentifier.length);
    }

    public void setSecureRealTimeTransportProtocolMasterKeyIdentifier(
            byte[] secureRealTimeTransportProtocolMasterKeyIdentifier) {
        this.secureRealTimeTransportProtocolMasterKeyIdentifier =
                secureRealTimeTransportProtocolMasterKeyIdentifier;
    }

    public UserMappingExtensionHintType getUserMappingExtensionHintType() {
        return userMappingExtensionHintType;
    }

    public void setUserMappingExtensionHintType(
            UserMappingExtensionHintType userMappingExtensionHintType) {
        this.userMappingExtensionHintType = userMappingExtensionHintType;
    }

    public List<CertificateType> getCertificateTypeDesiredTypes() {
        return certificateTypeDesiredTypes;
    }

    public void setCertificateTypeDesiredTypes(List<CertificateType> certificateTypeDesiredTypes) {
        this.certificateTypeDesiredTypes = certificateTypeDesiredTypes;
    }

    public List<CertificateType> getClientCertificateTypeDesiredTypes() {
        return clientCertificateTypeDesiredTypes;
    }

    public void setClientCertificateTypeDesiredTypes(
            List<CertificateType> clientCertificateTypeDesiredTypes) {
        this.clientCertificateTypeDesiredTypes = clientCertificateTypeDesiredTypes;
    }

    public List<CertificateType> getServerCertificateTypeDesiredTypes() {
        return serverCertificateTypeDesiredTypes;
    }

    public void setServerCertificateTypeDesiredTypes(
            List<CertificateType> serverCertificateTypeDesiredTypes) {
        this.serverCertificateTypeDesiredTypes = serverCertificateTypeDesiredTypes;
    }

    public List<AuthzDataFormat> getClientAuthzExtensionDataFormat() {
        return clientAuthzExtensionDataFormat;
    }

    public void setClientAuthzExtensionDataFormat(
            List<AuthzDataFormat> clientAuthzExtensionDataFormat) {
        this.clientAuthzExtensionDataFormat = clientAuthzExtensionDataFormat;
    }

    public Boolean isCertificateTypeExtensionMessageState() {
        return certificateTypeExtensionMessageState;
    }

    public void setCertificateTypeExtensionMessageState(
            Boolean certificateTypeExtensionMessageState) {
        this.certificateTypeExtensionMessageState = certificateTypeExtensionMessageState;
    }

    public List<AuthzDataFormat> getServerAuthzExtensionDataFormat() {
        return serverAuthzExtensionDataFormat;
    }

    public void setServerAuthzExtensionDataFormat(
            List<AuthzDataFormat> serverAuthzExtensionDataFormat) {
        this.serverAuthzExtensionDataFormat = serverAuthzExtensionDataFormat;
    }

    public List<TrustedAuthority> getTrustedCaIndicationExtensionAuthorities() {
        return trustedCaIndicationExtensionAuthorities;
    }

    public void setTrustedCaIndicationExtensionAuthorities(
            List<TrustedAuthority> trustedCaIndicationExtensionAuthorities) {
        this.trustedCaIndicationExtensionAuthorities = trustedCaIndicationExtensionAuthorities;
    }

    public Boolean isClientCertificateTypeExtensionMessageState() {
        return clientCertificateTypeExtensionMessageState;
    }

    public void setClientCertificateTypeExtensionMessageState(
            Boolean clientCertificateTypeExtensionMessageState) {
        this.clientCertificateTypeExtensionMessageState =
                clientCertificateTypeExtensionMessageState;
    }

    public Boolean isCachedInfoExtensionIsClientState() {
        return cachedInfoExtensionIsClientState;
    }

    public void setCachedInfoExtensionIsClientState(Boolean cachedInfoExtensionIsClientState) {
        this.cachedInfoExtensionIsClientState = cachedInfoExtensionIsClientState;
    }

    public List<CachedObject> getCachedObjectList() {
        return cachedObjectList;
    }

    public void setCachedObjectList(List<CachedObject> cachedObjectList) {
        this.cachedObjectList = cachedObjectList;
    }

    public List<RequestItemV2> getStatusRequestV2RequestList() {
        return statusRequestV2RequestList;
    }

    public void setStatusRequestV2RequestList(List<RequestItemV2> statusRequestV2RequestList) {
        this.statusRequestV2RequestList = statusRequestV2RequestList;
    }

    public Boolean isAddCertificateStatusRequestExtension() {
        return addCertificateStatusRequestExtension;
    }

    public void setAddCertificateStatusRequestExtension(
            Boolean addCertificateStatusRequestExtension) {
        this.addCertificateStatusRequestExtension = addCertificateStatusRequestExtension;
    }

    public Boolean isAddAlpnExtension() {
        return addAlpnExtension;
    }

    public void setAddAlpnExtension(Boolean addAlpnExtension) {
        this.addAlpnExtension = addAlpnExtension;
    }

    public Boolean isAddSRPExtension() {
        return addSRPExtension;
    }

    public void setAddSRPExtension(Boolean addSRPExtension) {
        this.addSRPExtension = addSRPExtension;
    }

    public Boolean isAddSRTPExtension() {
        return addSRTPExtension;
    }

    public void setAddSRTPExtension(Boolean addSRTPExtension) {
        this.addSRTPExtension = addSRTPExtension;
    }

    public Boolean isAddTruncatedHmacExtension() {
        return addTruncatedHmacExtension;
    }

    public void setAddTruncatedHmacExtension(Boolean addTruncatedHmacExtension) {
        this.addTruncatedHmacExtension = addTruncatedHmacExtension;
    }

    public Boolean isAddUserMappingExtension() {
        return addUserMappingExtension;
    }

    public void setAddUserMappingExtension(Boolean addUserMappingExtension) {
        this.addUserMappingExtension = addUserMappingExtension;
    }

    public Boolean isAddCertificateTypeExtension() {
        return addCertificateTypeExtension;
    }

    public void setAddCertificateTypeExtension(Boolean addCertificateTypeExtension) {
        this.addCertificateTypeExtension = addCertificateTypeExtension;
    }

    public Boolean isAddClientAuthzExtension() {
        return addClientAuthzExtension;
    }

    public void setAddClientAuthzExtension(Boolean addClientAuthzExtension) {
        this.addClientAuthzExtension = addClientAuthzExtension;
    }

    public Boolean isAddServerAuthzExtension() {
        return addServerAuthzExtension;
    }

    public void setAddServerAuthzExtension(Boolean addServerAuthzExtension) {
        this.addServerAuthzExtension = addServerAuthzExtension;
    }

    public Boolean isAddClientCertificateTypeExtension() {
        return addClientCertificateTypeExtension;
    }

    public void setAddClientCertificateTypeExtension(Boolean addClientCertificateTypeExtension) {
        this.addClientCertificateTypeExtension = addClientCertificateTypeExtension;
    }

    public Boolean isAddServerCertificateTypeExtension() {
        return addServerCertificateTypeExtension;
    }

    public void setAddServerCertificateTypeExtension(Boolean addServerCertificateTypeExtension) {
        this.addServerCertificateTypeExtension = addServerCertificateTypeExtension;
    }

    public Boolean isAddEncryptThenMacExtension() {
        return addEncryptThenMacExtension;
    }

    public void setAddEncryptThenMacExtension(Boolean addEncryptThenMacExtension) {
        this.addEncryptThenMacExtension = addEncryptThenMacExtension;
    }

    public Boolean isAddCachedInfoExtension() {
        return addCachedInfoExtension;
    }

    public void setAddCachedInfoExtension(Boolean addCachedInfoExtension) {
        this.addCachedInfoExtension = addCachedInfoExtension;
    }

    public Boolean isAddClientCertificateUrlExtension() {
        return addClientCertificateUrlExtension;
    }

    public void setAddClientCertificateUrlExtension(Boolean addClientCertificateUrlExtension) {
        this.addClientCertificateUrlExtension = addClientCertificateUrlExtension;
    }

    public Boolean isAddTrustedCaIndicationExtension() {
        return addTrustedCaIndicationExtension;
    }

    public void setAddTrustedCaIndicationExtension(Boolean addTrustedCaIndicationExtension) {
        this.addTrustedCaIndicationExtension = addTrustedCaIndicationExtension;
    }

    public Boolean isAddCertificateStatusRequestV2Extension() {
        return addCertificateStatusRequestV2Extension;
    }

    public void setAddCertificateStatusRequestV2Extension(
            Boolean addCertificateStatusRequestV2Extension) {
        this.addCertificateStatusRequestV2Extension = addCertificateStatusRequestV2Extension;
    }

    public List<CompressionMethod> getDefaultServerSupportedCompressionMethods() {
        return defaultServerSupportedCompressionMethods;
    }

    public void setDefaultServerSupportedCompressionMethods(
            List<CompressionMethod> defaultServerSupportedCompressionMethods) {
        this.defaultServerSupportedCompressionMethods = defaultServerSupportedCompressionMethods;
    }

    public void setDefaultServerSupportedCompressionMethods(
            CompressionMethod... defaultServerSupportedCompressionMethods) {
        this.defaultServerSupportedCompressionMethods =
                new ArrayList<>(Arrays.asList(defaultServerSupportedCompressionMethods));
    }

    public OutboundConnection getDefaultClientConnection() {
        return defaultClientConnection;
    }

    public void setDefaultClientConnection(OutboundConnection defaultClientConnection) {
        this.defaultClientConnection = defaultClientConnection;
    }

    public InboundConnection getDefaultServerConnection() {
        return defaultServerConnection;
    }

    public void setDefaultServerConnection(InboundConnection defaultServerConnection) {
        this.defaultServerConnection = defaultServerConnection;
    }

    public Boolean isReceiveFinalTcpSocketStateWithTimeout() {
        return receiveFinalTcpSocketStateWithTimeout;
    }

    public void setReceiveFinalTcpSocketStateWithTimeout(
            Boolean receiveFinalTcpSocketStateWithTimeout) {
        this.receiveFinalTcpSocketStateWithTimeout = receiveFinalTcpSocketStateWithTimeout;
    }

    public RunningModeType getDefaultRunningMode() {
        return defaultRunningMode;
    }

    public void setDefaultRunningMode(RunningModeType defaultRunningMode) {
        this.defaultRunningMode = defaultRunningMode;
    }

    public Boolean isStopActionsAfterFatal() {
        return stopActionsAfterFatal;
    }

    public void setStopActionsAfterFatal(Boolean stopActionsAfterFatal) {
        this.stopActionsAfterFatal = stopActionsAfterFatal;
    }

    public Boolean isStopActionAfterQuicConnCloseFrame() {
        return stopActionsAfterQuicConnectionClose;
    }

    public void setStopActionAfterQuicConnCloseFrame(Boolean stopActionsAfterQuicConnectionClose) {
        this.stopActionsAfterQuicConnectionClose = stopActionsAfterQuicConnectionClose;
    }

    public Boolean isFinishWithCloseNotify() {
        return finishWithCloseNotify;
    }

    public void setFinishWithCloseNotify(Boolean finishWithCloseNotify) {
        this.finishWithCloseNotify = finishWithCloseNotify;
    }

    public Boolean isIgnoreRetransmittedCcsInDtls() {
        return ignoreRetransmittedCcsInDtls;
    }

    public void setIgnoreRetransmittedCssInDtls(Boolean ignoreRetransmittedCcs) {
        this.ignoreRetransmittedCcsInDtls = ignoreRetransmittedCcs;
    }

    public Boolean isAddRetransmissionsToWorkflowTraceInDtls() {
        return addRetransmissionsToWorkflowTraceInDtls;
    }

    public void setAddRetransmissionsToWorkflowTraceInDtls(
            Boolean addRetransmissionsToWorkflowTrace) {
        this.addRetransmissionsToWorkflowTraceInDtls = addRetransmissionsToWorkflowTrace;
    }

    public int getMaxUDPRetransmissions() {
        return maxUDPRetransmissions;
    }

    public void setMaxUDPRetransmissions(int maxRetransmissions) {
        this.maxUDPRetransmissions = maxRetransmissions;
    }

    public List<FilterType> getOutputFilters() {
        return outputFilters;
    }

    public void setOutputFilters(List<FilterType> outputFilters) {
        this.outputFilters = outputFilters;
    }

    public Boolean isApplyFiltersInPlace() {
        return applyFiltersInPlace;
    }

    public void setApplyFiltersInPlace(Boolean applyFiltersInPlace) {
        this.applyFiltersInPlace = applyFiltersInPlace;
    }

    public Boolean isFiltersKeepUserSettings() {
        return filtersKeepUserSettings;
    }

    public void setFiltersKeepUserSettings(Boolean filtersKeepUserSettings) {
        this.filtersKeepUserSettings = filtersKeepUserSettings;
    }

    public byte[] getDefaultClientApplicationTrafficSecret() {
        return Arrays.copyOf(
                defaultClientApplicationTrafficSecret,
                defaultClientApplicationTrafficSecret.length);
    }

    public void setDefaultClientApplicationTrafficSecret(
            byte[] defaultClientApplicationTrafficSecret) {
        this.defaultClientApplicationTrafficSecret = defaultClientApplicationTrafficSecret;
    }

    public byte[] getDefaultServerApplicationTrafficSecret() {
        return Arrays.copyOf(
                defaultServerApplicationTrafficSecret,
                defaultServerApplicationTrafficSecret.length);
    }

    public void setDefaultServerApplicationTrafficSecret(
            byte[] defaultServerApplicationTrafficSecret) {
        this.defaultServerApplicationTrafficSecret = defaultServerApplicationTrafficSecret;
    }

    /**
     * @return the earlyData
     */
    public byte[] getEarlyData() {
        return Arrays.copyOf(earlyData, earlyData.length);
    }

    /**
     * @param earlyData the earlyData to set
     */
    public void setEarlyData(byte[] earlyData) {
        this.earlyData = earlyData;
    }

    /**
     * @return the defaultPskSets
     */
    public List<PskSet> getDefaultPskSets() {
        return defaultPskSets;
    }

    /**
     * @param defaultPskSets the defaultPskSets to set
     */
    public void setDefaultPskSets(List<PskSet> defaultPskSets) {
        this.defaultPskSets = defaultPskSets;
    }

    /**
     * @return the psk
     */
    public byte[] getPsk() {
        return Arrays.copyOf(psk, psk.length);
    }

    /**
     * @param psk the psk to set
     */
    public void setPsk(byte[] psk) {
        this.psk = psk;
    }

    /**
     * @return the defaultSessionTicketAgeAdd
     */
    public byte[] getDefaultSessionTicketAgeAdd() {
        return Arrays.copyOf(defaultSessionTicketAgeAdd, defaultSessionTicketAgeAdd.length);
    }

    /**
     * @param defaultSessionTicketAgeAdd the defaultSessionTicketAgeAdd to set
     */
    public void setDefaultSessionTicketAgeAdd(byte[] defaultSessionTicketAgeAdd) {
        this.defaultSessionTicketAgeAdd = defaultSessionTicketAgeAdd;
    }

    /**
     * @return the defaultSessionTicketNonce
     */
    public byte[] getDefaultSessionTicketNonce() {
        return Arrays.copyOf(defaultSessionTicketNonce, defaultSessionTicketNonce.length);
    }

    /**
     * @param defaultSessionTicketNonce the defaultSessionTicketNonce to set
     */
    public void setDefaultSessionTicketNonce(byte[] defaultSessionTicketNonce) {
        this.defaultSessionTicketNonce = defaultSessionTicketNonce;
    }

    /**
     * @return the defaultSessionTicketIdentity
     */
    public byte[] getDefaultSessionTicketIdentity() {
        return Arrays.copyOf(defaultSessionTicketIdentity, defaultSessionTicketIdentity.length);
    }

    /**
     * @param defaultSessionTicketIdentity the defaultSessionTicketIdentity to set
     */
    public void setDefaultSessionTicketIdentity(byte[] defaultSessionTicketIdentity) {
        this.defaultSessionTicketIdentity = defaultSessionTicketIdentity;
    }

    /**
     * @return the clientEarlyTrafficSecret
     */
    public byte[] getClientEarlyTrafficSecret() {
        return Arrays.copyOf(clientEarlyTrafficSecret, clientEarlyTrafficSecret.length);
    }

    /**
     * @param clientEarlyTrafficSecret the clientEarlyTrafficSecret to set
     */
    public void setClientEarlyTrafficSecret(byte[] clientEarlyTrafficSecret) {
        this.clientEarlyTrafficSecret = clientEarlyTrafficSecret;
    }

    /**
     * @return the earlySecret
     */
    public byte[] getEarlySecret() {
        return Arrays.copyOf(earlySecret, earlySecret.length);
    }

    /**
     * @param earlySecret the earlySecret to set
     */
    public void setEarlySecret(byte[] earlySecret) {
        this.earlySecret = earlySecret;
    }

    /**
     * @return the earlyDataCipherSuite
     */
    public CipherSuite getEarlyDataCipherSuite() {
        return earlyDataCipherSuite;
    }

    /**
     * @param earlyDataCipherSuite the earlyDataCipherSuite to set
     */
    public void setEarlyDataCipherSuite(CipherSuite earlyDataCipherSuite) {
        this.earlyDataCipherSuite = earlyDataCipherSuite;
    }

    /**
     * @return the earlyDataPsk
     */
    public byte[] getEarlyDataPsk() {
        return Arrays.copyOf(earlyDataPsk, earlyDataPsk.length);
    }

    /**
     * @param earlyDataPsk the earlyDataPsk to set
     */
    public void setEarlyDataPsk(byte[] earlyDataPsk) {
        this.earlyDataPsk = earlyDataPsk;
    }

    /**
     * @return the usePsk
     */
    public Boolean isUsePsk() {
        return usePsk;
    }

    /**
     * @param usePsk the usePsk to set
     */
    public void setUsePsk(Boolean usePsk) {
        this.usePsk = usePsk;
    }

    public List<String> getDefaultProposedAlpnProtocols() {
        return defaultProposedAlpnProtocols;
    }

    public void setDefaultProposedAlpnProtocols(List<String> defaultProposedAlpnProtocols) {
        this.defaultProposedAlpnProtocols = defaultProposedAlpnProtocols;
    }

    public void setDefaultProposedAlpnProtocols(String... alpnAnnouncedProtocols) {
        this.defaultProposedAlpnProtocols = new ArrayList<>(Arrays.asList(alpnAnnouncedProtocols));
    }

    public QuicTransportParameters getDefaultQuicTransportParameters() {
        return defaultQuicTransportParameters;
    }

    public void setDefaultQuicTransportParameters(
            QuicTransportParameters defaultQuicTransportParameters) {
        this.defaultQuicTransportParameters = defaultQuicTransportParameters;
    }

    public Boolean isEchoQuic() {
        return echoQuic;
    }

    public void setEchoQuic(Boolean echoQuic) {
        this.echoQuic = echoQuic;
    }

    public NamedGroup getDefaultEcCertificateCurve() {
        return defaultEcCertificateCurve;
    }

    public void setDefaultEcCertificateCurve(NamedGroup defaultEcCertificateCurve) {
        this.defaultEcCertificateCurve = defaultEcCertificateCurve;
    }

    public StarttlsType getStarttlsType() {
        return starttlsType;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        this.starttlsType = starttlsType;
    }

    public KeyShareStoreEntry getDefaultServerKeyShareEntry() {
        return defaultServerKeyShareEntry;
    }

    public void setDefaultServerKeyShareEntry(KeyShareStoreEntry defaultServerKeyShareEntry) {
        this.defaultServerKeyShareEntry = defaultServerKeyShareEntry;
    }

    public byte[] getDefaultHandshakeSecret() {
        return Arrays.copyOf(defaultHandshakeSecret, defaultHandshakeSecret.length);
    }

    public void setDefaultHandshakeSecret(byte[] defaultHandshakeSecret) {
        this.defaultHandshakeSecret = defaultHandshakeSecret;
    }

    public String getDefaultClientPWDUsername() {
        return defaultClientPWDUsername;
    }

    public void setDefaultClientPWDUsername(String username) {
        this.defaultClientPWDUsername = username;
    }

    public byte[] getDefaultServerPWDSalt() {
        return Arrays.copyOf(defaultServerPWDSalt, defaultServerPWDSalt.length);
    }

    public void setDefaultServerPWDSalt(byte[] salt) {
        this.defaultServerPWDSalt = salt;
    }

    public String getDefaultPWDPassword() {
        return defaultPWDPassword;
    }

    public void setDefaultPWDPassword(String password) {
        this.defaultPWDPassword = password;
    }

    public byte[] getDefaultServerPWDPrivate() {
        return Arrays.copyOf(defaultServerPWDPrivate, defaultServerPWDPrivate.length);
    }

    public void setDefaultServerPWDPrivate(byte[] defaultServerPWDPrivate) {
        this.defaultServerPWDPrivate = defaultServerPWDPrivate;
    }

    public byte[] getDefaultServerPWDMask() {
        return Arrays.copyOf(defaultServerPWDMask, defaultServerPWDMask.length);
    }

    public void setDefaultServerPWDMask(byte[] defaultServerPWDMask) {
        this.defaultServerPWDMask = defaultServerPWDMask;
    }

    public byte[] getDefaultClientPWDPrivate() {
        return Arrays.copyOf(defaultClientPWDPrivate, defaultClientPWDPrivate.length);
    }

    public void setDefaultClientPWDPrivate(byte[] defaultClientPWDPrivate) {
        this.defaultClientPWDPrivate = defaultClientPWDPrivate;
    }

    public byte[] getDefaultClientPWDMask() {
        return Arrays.copyOf(defaultClientPWDMask, defaultClientPWDMask.length);
    }

    public void setDefaultClientPWDMask(byte[] defaultClientPWDMask) {
        this.defaultClientPWDMask = defaultClientPWDMask;
    }

    public NamedGroup getDefaultPWDProtectGroup() {
        return defaultPWDProtectGroup;
    }

    public void setDefaultPWDProtectGroup(NamedGroup defaultPWDProtectGroup) {
        this.defaultPWDProtectGroup = defaultPWDProtectGroup;
    }

    public Point getDefaultServerPWDProtectPublicKey() {
        return defaultServerPWDProtectPublicKey;
    }

    public void setDefaultServerPWDProtectPublicKey(Point defaultServerPWDProtectPublicKey) {
        this.defaultServerPWDProtectPublicKey = defaultServerPWDProtectPublicKey;
    }

    public BigInteger getDefaultServerPWDProtectPrivateKey() {
        return defaultServerPWDProtectPrivateKey;
    }

    public void setDefaultServerPWDProtectPrivateKey(BigInteger defaultServerPWDProtectPrivateKey) {
        this.defaultServerPWDProtectPrivateKey = defaultServerPWDProtectPrivateKey;
    }

    public BigInteger getDefaultServerPWDProtectRandomSecret() {
        return defaultServerPWDProtectRandomSecret;
    }

    public void setDefaultServerPWDProtectRandomSecret(
            BigInteger defaultServerPWDProtectRandomSecret) {
        this.defaultServerPWDProtectRandomSecret = defaultServerPWDProtectRandomSecret;
    }

    public Boolean isAddPWDProtectExtension() {
        return addPWDProtectExtension;
    }

    public void setAddPWDProtectExtension(Boolean addPWDProtectExtension) {
        this.addPWDProtectExtension = addPWDProtectExtension;
    }

    public Boolean isStopTraceAfterUnexpected() {
        return stopTraceAfterUnexpected;
    }

    public void setStopTraceAfterUnexpected(Boolean stopTraceAfterUnexpected) {
        this.stopTraceAfterUnexpected = stopTraceAfterUnexpected;
    }

    public List<CipherSuite> getClientSupportedEsniCipherSuites() {
        return this.clientSupportedEsniCipherSuites;
    }

    public void setClientSupportedEsniCipherSuites(
            List<CipherSuite> clientSupportedEsniCipherSuites) {
        this.clientSupportedEsniCipherSuites = clientSupportedEsniCipherSuites;
    }

    public void setClientSupportedEsniCipherSuites(CipherSuite... clientSupportedEsniCipherSuites) {
        this.clientSupportedEsniCipherSuites =
                new ArrayList<>(Arrays.asList(clientSupportedEsniCipherSuites));
    }

    public List<NamedGroup> getClientSupportedEsniNamedGroups() {
        return this.clientSupportedEsniNamedGroups;
    }

    public void setClientSupportedEsniNamedGroups(List<NamedGroup> clientSupportedEsniNamedGroups) {
        this.clientSupportedEsniNamedGroups = clientSupportedEsniNamedGroups;
    }

    public final void setClientSupportedEsniNamedGroups(
            NamedGroup... clientSupportedEsniNamedGroups) {
        this.clientSupportedEsniNamedGroups =
                new ArrayList<>(Arrays.asList(clientSupportedEsniNamedGroups));
    }

    public List<KeyShareEntry> getEsniServerKeyPairs() {
        return this.esniServerKeyPairs;
    }

    public void setEsniServerKeyPairs(List<KeyShareEntry> esniServerKeyPairs) {
        this.esniServerKeyPairs = esniServerKeyPairs;
    }

    public final void setEsniServerKeyPairs(KeyShareEntry... esniServerKeyPairs) {
        this.esniServerKeyPairs = new ArrayList<>(Arrays.asList(esniServerKeyPairs));
    }

    public byte[] getDefaultEsniClientNonce() {
        return Arrays.copyOf(defaultEsniClientNonce, defaultEsniClientNonce.length);
    }

    public void setDefaultEsniClientNonce(byte[] defaultEsniClientNonce) {
        this.defaultEsniClientNonce = defaultEsniClientNonce;
    }

    public BigInteger getDefaultEchClientPrivateKey() {
        return defaultEchClientPrivateKey;
    }

    public void setDefaultEchClientPrivateKey(BigInteger defaultEchClientPrivateKey) {
        this.defaultEchClientPrivateKey = defaultEchClientPrivateKey;
    }

    public BigInteger getDefaultEchServerPrivateKey() {
        return defaultEchServerPrivateKey;
    }

    public void setDefaultEchServerPrivateKey(BigInteger defaultEchServerPrivateKey) {
        this.defaultEchServerPrivateKey = defaultEchServerPrivateKey;
    }

    public byte[] getDefaultEsniServerNonce() {
        return Arrays.copyOf(defaultEsniServerNonce, defaultEsniServerNonce.length);
    }

    public void setDefaultEsniServerNonce(byte[] defaultEsniServerNonce) {
        this.defaultEsniServerNonce = defaultEsniServerNonce;
    }

    public byte[] getDefaultEsniRecordBytes() {
        return Arrays.copyOf(defaultEsniRecordBytes, defaultEsniRecordBytes.length);
    }

    public void setDefaultEsniRecordBytes(byte[] defaultEsniRecordBytes) {
        this.defaultEsniRecordBytes = defaultEsniRecordBytes;
    }

    public EsniDnsKeyRecordVersion getDefaultEsniRecordVersion() {
        return defaultEsniRecordVersion;
    }

    public void setDefaultEsniRecordVersion(EsniDnsKeyRecordVersion defaultEsniRecordVersion) {
        this.defaultEsniRecordVersion = defaultEsniRecordVersion;
    }

    public byte[] getDefaultEsniRecordChecksum() {
        return Arrays.copyOf(defaultEsniRecordChecksum, defaultEsniRecordChecksum.length);
    }

    public void setDefaultEsniRecordChecksum(byte[] defaultEsniRecordChecksum) {
        this.defaultEsniRecordChecksum = defaultEsniRecordChecksum;
    }

    public List<KeyShareStoreEntry> getDefaultEsniServerKeyShareEntries() {
        return defaultEsniServerKeyShareEntries;
    }

    public void setDefaultEsniServerKeyShareEntries(
            List<KeyShareStoreEntry> defaultEsniServerKeyShareEntries) {
        this.defaultEsniServerKeyShareEntries = defaultEsniServerKeyShareEntries;
    }

    public List<CipherSuite> getDefaultEsniServerCipherSuites() {
        return defaultEsniServerCipherSuites;
    }

    public void setDefaultEsniServerCipherSuites(List<CipherSuite> defaultEsniServerCipherSuites) {
        this.defaultEsniServerCipherSuites = defaultEsniServerCipherSuites;
    }

    public Integer getDefaultEsniPaddedLength() {
        return defaultEsniPaddedLength;
    }

    public void setDefaultEsniPaddedLength(Integer defaultEsniPaddedLength) {
        this.defaultEsniPaddedLength = defaultEsniPaddedLength;
    }

    public Long getDefaultEsniNotBefore() {
        return defaultEsniNotBefore;
    }

    public void setDefaultEsniNotBefore(Long defaultEsniNotBefore) {
        this.defaultEsniNotBefore = defaultEsniNotBefore;
    }

    public Long getDefaultEsniNotAfter() {
        return defaultEsniNotAfter;
    }

    public void setDefaultEsniNotAfter(Long defaultEsniNotAfter) {
        this.defaultEsniNotAfter = defaultEsniNotAfter;
    }

    public List<ExtensionType> getDefaultEsniExtensions() {
        return defaultEsniExtensions;
    }

    public void setDefaultEsniExtensions(List<ExtensionType> defaultEsniExtensions) {
        this.defaultEsniExtensions = defaultEsniExtensions;
    }

    public Boolean isWriteKeylogFile() {
        return writeKeylogFile;
    }

    public void setWriteKeylogFile(Boolean writeKeylogFile) {
        this.writeKeylogFile = writeKeylogFile;
    }

    public String getKeylogFilePath() {
        return keylogFilePath;
    }

    public void setKeylogFilePath(String keylogFilePath) {
        this.keylogFilePath = keylogFilePath;
    }

    public BigInteger getDefaultEsniClientPrivateKey() {
        return defaultEsniClientPrivateKey;
    }

    public void setDefaultEsniClientPrivateKey(BigInteger defaultEsniClientPrivateKey) {
        this.defaultEsniClientPrivateKey = defaultEsniClientPrivateKey;
    }

    public List<NamedGroup> getDefaultClientKeyShareNamedGroups() {
        return defaultClientKeyShareNamedGroups;
    }

    public void setDefaultClientKeyShareNamedGroups(
            List<NamedGroup> defaultClientKeyShareNamedGroups) {
        this.defaultClientKeyShareNamedGroups = defaultClientKeyShareNamedGroups;
    }

    public void setDefaultClientKeyShareNamedGroups(
            NamedGroup... defaultClientKeyShareNamedGroups) {
        this.defaultClientKeyShareNamedGroups =
                new ArrayList<>(Arrays.asList(defaultClientKeyShareNamedGroups));
    }

    public List<KeyShareStoreEntry> getDefaultClientKeyStoreEntries() {
        return defaultClientKeyStoreEntries;
    }

    public void setDefaultClientKeyStoreEntries(
            List<KeyShareStoreEntry> defaultClientKeyStoreEntries) {
        this.defaultClientKeyStoreEntries = defaultClientKeyStoreEntries;
    }

    public List<ActionOption> getMessageFactoryActionOptions() {
        return messageFactoryActionOptions;
    }

    public void setMessageFactoryActionOptions(List<ActionOption> messageFactoryActionOptions) {
        this.messageFactoryActionOptions = messageFactoryActionOptions;
    }

    public Boolean isRetryFailedClientTcpSocketInitialization() {
        return retryFailedClientTcpSocketInitialization;
    }

    public void setRetryFailedClientTcpSocketInitialization(
            Boolean retryFailedClientTcpSocketInitialization) {
        this.retryFailedClientTcpSocketInitialization = retryFailedClientTcpSocketInitialization;
    }

    public Boolean isResetClientSourcePort() {
        return resetClientSourcePort;
    }

    public void setResetClientSourcePort(Boolean resetClientSourcePort) {
        this.resetClientSourcePort = resetClientSourcePort;
    }

    public Boolean isLimitPsksToOne() {
        return limitPsksToOne;
    }

    public void setLimitPsksToOne(Boolean limitPsksToOne) {
        this.limitPsksToOne = limitPsksToOne;
    }

    public Boolean getPreserveMessageRecordRelation() {
        return preserveMessageRecordRelation;
    }

    public void setPreserveMessageRecordRelation(Boolean preserveMessageRecordRelation) {
        this.preserveMessageRecordRelation = preserveMessageRecordRelation;
    }

    public Integer getDefaultMaxEarlyDataSize() {
        return defaultMaxEarlyDataSize;
    }

    public void setDefaultMaxEarlyDataSize(Integer defaultMaxEarlyDataSize) {
        this.defaultMaxEarlyDataSize = defaultMaxEarlyDataSize;
    }

    public byte[] getDefaultLastClientHello() {
        return Arrays.copyOf(defaultLastClientHello, defaultLastClientHello.length);
    }

    public void setDefaultLastClientHello(byte[] defaultLastClientHello) {
        this.defaultLastClientHello = defaultLastClientHello;
    }

    public int getPreferredCertRsaKeySize() {
        return preferredCertRsaKeySize;
    }

    public void setPreferredCertRsaKeySize(int preferredCertRsaKeySize) {
        this.preferredCertRsaKeySize = preferredCertRsaKeySize;
    }

    public int getPreferredCertDssKeySize() {
        return preferredCertDssKeySize;
    }

    public void setPreferredCertDssKeySize(int preferredCertDssKeySize) {
        this.preferredCertDssKeySize = preferredCertDssKeySize;
    }

    public byte[] getDefaultExtensionCookie() {
        return defaultExtensionCookie;
    }

    public void setDefaultExtensionCookie(byte[] defaultExtensionCookie) {
        this.defaultExtensionCookie = defaultExtensionCookie;
    }

    public Boolean isAddCookieExtension() {
        return addCookieExtension;
    }

    public void setAddCookieExtension(Boolean addCookieExtension) {
        this.addCookieExtension = addCookieExtension;
    }

    public Boolean isEncryptChangeCipherSpec() {
        return encryptChangeCipherSpecTls13;
    }

    public void setEncryptChangeCipherSpec(Boolean encryptChangeCipherSpec) {
        this.encryptChangeCipherSpecTls13 = encryptChangeCipherSpec;
    }

    public KeyUpdateRequest getDefaultKeyUpdateRequestMode() {
        return defaultKeyUpdateRequestMode;
    }

    public void setDefaultKeyUpdateRequestMode(KeyUpdateRequest defaultKeyUpdateRequestMode) {
        this.defaultKeyUpdateRequestMode = defaultKeyUpdateRequestMode;
    }

    public CipherAlgorithm getSessionTicketCipherAlgorithm() {
        return sessionTicketCipherAlgorithm;
    }

    public void setSessionTicketCipherAlgorithm(CipherAlgorithm sessionTicketCipherAlgorithm) {
        this.sessionTicketCipherAlgorithm = sessionTicketCipherAlgorithm;
    }

    public MacAlgorithm getSessionTicketMacAlgorithm() {
        return sessionTicketMacAlgorithm;
    }

    public void setSessionTicketMacAlgorithm(MacAlgorithm sessionTicketMacAlgorithm) {
        this.sessionTicketMacAlgorithm = sessionTicketMacAlgorithm;
    }

    public byte[] getDefaultClientTicketResumptionSessionId() {
        return defaultClientTicketResumptionSessionId;
    }

    public void setDefaultClientTicketResumptionSessionId(
            byte[] defaultClientTicketResumptionSessionId) {
        this.defaultClientTicketResumptionSessionId = defaultClientTicketResumptionSessionId;
    }

    public List<ServerNamePair> getDefaultSniHostnames() {
        return defaultSniHostnames;
    }

    public void setDefaultSniHostnames(List<ServerNamePair> defaultSniHostnames) {
        this.defaultSniHostnames = defaultSniHostnames;
    }

    public String getDefaultDnsServer() {
        return defaultDnsServer;
    }

    public void setDefaultDnsServer(String defaultDnsServer) {
        this.defaultDnsServer = defaultDnsServer;
    }

    public EchConfig getDefaultEchConfig() {
        return defaultEchConfig;
    }

    public void setDefaultEchConfig(EchConfig defaultEchConfig) {
        this.defaultEchConfig = defaultEchConfig;
    }

    public Integer getDefaultMaxEchAlpnPadding() {
        return defaultMaxEchAlpnPadding;
    }

    public void setDefaultMaxEchAlpnPadding(Integer defaultMaxEchAlpnPadding) {
        this.defaultMaxEchAlpnPadding = defaultMaxEchAlpnPadding;
    }

    public StackConfiguration getDefaultLayerConfiguration() {
        return defaultLayerConfiguration;
    }

    public void setDefaultLayerConfiguration(StackConfiguration defaultLayerConfiguration) {
        this.defaultLayerConfiguration = defaultLayerConfiguration;
    }

    public byte[] getDefaultConnectionId() {
        return Arrays.copyOf(defaultConnectionId, defaultConnectionId.length);
    }

    public void setDefaultConnectionId(byte[] defaultConnectionId) {
        this.defaultConnectionId = defaultConnectionId;
    }

    public String getDefaultDebugContent() {
        return defaultDebugContent;
    }

    public void setDefaultDebugContent(String defaultDebugContent) {
        this.defaultDebugContent = defaultDebugContent;
    }

    public Integer getDefaultNumberOfRequestedConnectionIds() {
        return defaultNumberOfRequestedConnectionIds;
    }

    public void setDefaultNumberOfRequestedConnectionIds(
            Integer defaultNumberOfRequestedConnectionIds) {
        this.defaultNumberOfRequestedConnectionIds = defaultNumberOfRequestedConnectionIds;
    }

    public ConnectionIdUsage getDefaultUsageOfSentConnectionIds() {
        return defaultUsageOfSentConnectionIds;
    }

    public void setDefaultUsageOfSentConnectionIds(
            ConnectionIdUsage defaultUsageofSentConnectionIds) {
        this.defaultUsageOfSentConnectionIds = defaultUsageofSentConnectionIds;
    }

    public Boolean isAddConnectionIdExtension() {
        return addConnectionIdExtension;
    }

    public void setAddConnectionIdExtension(Boolean addConnectionIdExtension) {
        this.addConnectionIdExtension = addConnectionIdExtension;
    }

    public List<SSL2CipherSuite> getDefaultServerSupportedSSL2CipherSuites() {
        return defaultServerSupportedSSL2CipherSuites;
    }

    public void setDefaultServerSupportedSSL2CipherSuites(
            List<SSL2CipherSuite> defaultServerSupportedSSL2CipherSuites) {
        this.defaultServerSupportedSSL2CipherSuites = defaultServerSupportedSSL2CipherSuites;
    }

    public Boolean getSendHandshakeMessagesWithinSingleRecord() {
        return sendHandshakeMessagesWithinSingleRecord;
    }

    public void setSendHandshakeMessagesWithinSingleRecord(
            Boolean sendHandshakeMessagesWithinSingleRecord) {
        this.sendHandshakeMessagesWithinSingleRecord = sendHandshakeMessagesWithinSingleRecord;
    }

    public Boolean getUseDtls13HeaderSeqNumSizeLongEncoding() {
        return useDtls13HeaderSeqNumSizeLongEncoding;
    }

    public void setUseDtls13HeaderSeqNumSizeLongEncoding(
            Boolean useDtls13HeaderSeqNumSizeLongEncoding) {
        this.useDtls13HeaderSeqNumSizeLongEncoding = useDtls13HeaderSeqNumSizeLongEncoding;
    }

    public Boolean getRetransmitAcknowledgedRecordsInDtls13() {
        return retransmitAcknowledgedRecordsInDtls13;
    }

    public void setRetransmitAcknowledgedRecordsInDtls13(
            Boolean retransmitAcknowledgedRecordsInDtls13) {
        this.retransmitAcknowledgedRecordsInDtls13 = retransmitAcknowledgedRecordsInDtls13;
    }

    public BigInteger getDefaultServerEphemeralDhGenerator() {
        return defaultServerEphemeralDhGenerator;
    }

    public void setDefaultServerEphemeralDhGenerator(BigInteger defaultServerEphemeralDhGenerator) {
        this.defaultServerEphemeralDhGenerator = defaultServerEphemeralDhGenerator;
    }

    public BigInteger getDefaultServerEphemeralDhModulus() {
        return defaultServerEphemeralDhModulus;
    }

    public void setDefaultServerEphemeralDhModulus(BigInteger defaultServerEphemeralDhModulus) {
        this.defaultServerEphemeralDhModulus = defaultServerEphemeralDhModulus;
    }

    public BigInteger getDefaultServerEphemeralDhPrivateKey() {
        return defaultServerEphemeralDhPrivateKey;
    }

    public void setDefaultServerEphemeralDhPrivateKey(
            BigInteger defaultServerEphemeralDhPrivateKey) {
        this.defaultServerEphemeralDhPrivateKey = defaultServerEphemeralDhPrivateKey;
    }

    public BigInteger getDefaultClientEphemeralDhPrivateKey() {
        return defaultClientEphemeralDhPrivateKey;
    }

    public void setDefaultClientEphemeralDhPrivateKey(
            BigInteger defaultClientEphemeralDhPrivateKey) {
        this.defaultClientEphemeralDhPrivateKey = defaultClientEphemeralDhPrivateKey;
    }

    public BigInteger getDefaultServerEphemeralDhPublicKey() {
        return defaultServerEphemeralDhPublicKey;
    }

    public void setDefaultServerEphemeralDhPublicKey(BigInteger defaultServerEphemeralDhPublicKey) {
        this.defaultServerEphemeralDhPublicKey = defaultServerEphemeralDhPublicKey;
    }

    public BigInteger getDefaultClientEphemeralDhPublicKey() {
        return defaultClientEphemeralDhPublicKey;
    }

    public void setDefaultClientEphemeralDhPublicKey(BigInteger defaultClientEphemeralDhPublicKey) {
        this.defaultClientEphemeralDhPublicKey = defaultClientEphemeralDhPublicKey;
    }

    public BigInteger getDefaultServerEphemeralEcPrivateKey() {
        return defaultServerEphemeralEcPrivateKey;
    }

    public void setDefaultServerEphemeralEcPrivateKey(
            BigInteger defaultServerEphemeralEcPrivateKey) {
        this.defaultServerEphemeralEcPrivateKey = defaultServerEphemeralEcPrivateKey;
    }

    public BigInteger getDefaultClientEphemeralEcPrivateKey() {
        return defaultClientEphemeralEcPrivateKey;
    }

    public void setDefaultClientEphemeralEcPrivateKey(
            BigInteger defaultClientEphemeralEcPrivateKey) {
        this.defaultClientEphemeralEcPrivateKey = defaultClientEphemeralEcPrivateKey;
    }

    public BigInteger getDefaultServerEphemeralRsaExportModulus() {
        return defaultServerEphemeralRsaExportModulus;
    }

    public void setDefaultServerEphemeralRsaExportModulus(
            BigInteger defaultServerEphemeralRsaExportModulus) {
        this.defaultServerEphemeralRsaExportModulus = defaultServerEphemeralRsaExportModulus;
    }

    public BigInteger getDefaultServerEphemeralRsaExportPublicKey() {
        return defaultServerEphemeralRsaExportPublicKey;
    }

    public void setDefaultServerEphemeralRsaExportPublicKey(
            BigInteger defaultServerEphemeralRsaExportPublicKey) {
        this.defaultServerEphemeralRsaExportPublicKey = defaultServerEphemeralRsaExportPublicKey;
    }

    public BigInteger getDefaultServerEphemeralRsaExportPrivateKey() {
        return defaultServerEphemeralRsaExportPrivateKey;
    }

    public void setDefaultServerEphemeralRsaExportPrivateKey(
            BigInteger defaultServerEphemeralRsaExportPrivateKey) {
        this.defaultServerEphemeralRsaExportPrivateKey = defaultServerEphemeralRsaExportPrivateKey;
    }

    public BigInteger getDefaultServerEphemeralDhExportGenerator() {
        return defaultServerEphemeralDhExportGenerator;
    }

    public void setDefaultServerEphemeralDhExportGenerator(
            BigInteger defaultServerEphemeralDhExportGenerator) {
        this.defaultServerEphemeralDhExportGenerator = defaultServerEphemeralDhExportGenerator;
    }

    public BigInteger getDefaultServerEphemeralDhExportModulus() {
        return defaultServerEphemeralDhExportModulus;
    }

    public void setDefaultServerEphemeralDhExportModulus(
            BigInteger defaultServerEphemeralDhExportModulus) {
        this.defaultServerEphemeralDhExportModulus = defaultServerEphemeralDhExportModulus;
    }

    public BigInteger getDefaultServerEphemeralDhExportPublicKey() {
        return defaultServerEphemeralDhExportPublicKey;
    }

    public void setDefaultServerEphemeralDhExportPublicKey(
            BigInteger defaultServerEphemeralDhExportPublicKey) {
        this.defaultServerEphemeralDhExportPublicKey = defaultServerEphemeralDhExportPublicKey;
    }

    public BigInteger getDefaultServerEphemeralDhExportPrivateKey() {
        return defaultServerEphemeralDhExportPrivateKey;
    }

    public void setDefaultServerEphemeralDhExportPrivateKey(
            BigInteger defaultServerEphemeralDhExportPrivateKey) {
        this.defaultServerEphemeralDhExportPrivateKey = defaultServerEphemeralDhExportPrivateKey;
    }

    public Boolean getAutoAdjustSignatureAndHashAlgorithm() {
        return autoAdjustSignatureAndHashAlgorithm;
    }

    public void setAutoAdjustSignatureAndHashAlgorithm(
            Boolean autoAdjustSignatureAndHashAlgorithm) {
        this.autoAdjustSignatureAndHashAlgorithm = autoAdjustSignatureAndHashAlgorithm;
    }

    public boolean isRespectPeerRecordSizeLimitations() {
        return respectPeerRecordSizeLimitations;
    }

    public void setRespectPeerRecordSizeLimitations(boolean respectPeerRecordSizeLimitations) {
        this.respectPeerRecordSizeLimitations = respectPeerRecordSizeLimitations;
    }

    public Integer getDefaultAssumedMaxReceiveLimit() {
        return defaultAssumedMaxReceiveLimit;
    }

    public void setDefaultAssumedMaxReceiveLimit(Integer defaultAssumedMaxReceiveLimit) {
        this.defaultAssumedMaxReceiveLimit = defaultAssumedMaxReceiveLimit;
    }

    public BigInteger getDefaultKeySharePrivateKey(NamedGroup group) {
        return defaultKeySharePrivateMap.getOrDefault(group, new BigInteger("FFFF", 16));
    }

    public void setDefaultKeySharePrivateKey(NamedGroup group, BigInteger privateKey) {
        if (defaultKeySharePrivateMap.containsKey(group)) {
            defaultKeySharePrivateMap.remove(group);
        }
        defaultKeySharePrivateMap.put(group, privateKey);
    }

    public SrtpProtectionProfile getDefaultSelectedSrtpProtectionProfile() {
        return defaultSelectedSrtpProtectionProfile;
    }

    public void setDefaultSelectedSrtpProtectionProfile(
            SrtpProtectionProfile defaultSelectedSrtpProtectionProfile) {
        this.defaultSelectedSrtpProtectionProfile = defaultSelectedSrtpProtectionProfile;
    }

    public Boolean isRespectClientProposedExtensions() {
        return respectClientProposedExtensions;
    }

    public void setRespectClientProposedExtensions(Boolean respectClientProposedExtensions) {
        this.respectClientProposedExtensions = respectClientProposedExtensions;
    }

    public Boolean getQuic() {
        return isQuic;
    }

    public void setQuic(Boolean quic) {
        isQuic = quic;
    }

    public Boolean getQuicRetryFlowRequired() {
        return quicRetryFlowRequired;
    }

    public void setQuicRetryFlowRequired(Boolean quicRetryFlowRequired) {
        this.quicRetryFlowRequired = quicRetryFlowRequired;
    }

    public byte[] getDefaultQuicPathChallange() {
        return defaultQuicPathChallange;
    }

    public void setDefaultQuicPathChallange(byte[] defaultQuicPathChallange) {
        this.defaultQuicPathChallange = defaultQuicPathChallange;
    }

    public byte[] getDefaultQuicNewToken() {
        return defaultQuicNewToken;
    }

    public void setDefaultQuicNewToken(byte[] defaultQuicNewToken) {
        this.defaultQuicNewToken = defaultQuicNewToken;
    }
}
