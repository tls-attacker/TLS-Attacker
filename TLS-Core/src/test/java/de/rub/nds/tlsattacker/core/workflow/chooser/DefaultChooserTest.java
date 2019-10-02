/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class DefaultChooserTest {

    private Chooser chooser;
    private TlsContext context;
    private Config config;
    private Random random;

    public DefaultChooserTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        chooser = context.getChooser();
        config = chooser.getConfig();
        random = new Random(0);
    }

    /**
     * Test of getClientSupportedPointFormats method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedPointFormats() {
        List<ECPointFormat> formatList = new LinkedList<>();
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        config.setDefaultClientSupportedPointFormats(formatList);
        assertTrue(config.getDefaultClientSupportedPointFormats().size() == 8);
        assertTrue(chooser.getClientSupportedPointFormats().size() == 8);
        context.setClientPointFormatsList(new LinkedList<ECPointFormat>());
        assertTrue(chooser.getClientSupportedPointFormats().isEmpty());
    }

    /**
     * Test of getSelectedSigHashAlgorithm method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedSigHashAlgorithm() {
        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        assertEquals(config.getDefaultSelectedSignatureAndHashAlgorithm(), SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        assertEquals(chooser.getSelectedSigHashAlgorithm(), SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        context.setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.DSA_SHA1);
        assertEquals(chooser.getSelectedSigHashAlgorithm(), SignatureAndHashAlgorithm.DSA_SHA1);
    }

    /**
     * Test of getClientSupportedNamedGroups method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedNamedCurves() {
        List<NamedGroup> curveList = new LinkedList<>();
        curveList.add(NamedGroup.BRAINPOOLP256R1);
        curveList.add(NamedGroup.ECDH_X448);
        curveList.add(NamedGroup.SECP160K1);
        config.setDefaultClientNamedGroups(curveList);
        assertTrue(config.getDefaultClientNamedGroups().size() == 3);
        assertTrue(chooser.getClientSupportedNamedGroups().size() == 3);
        context.setClientNamedGroupsList(new LinkedList<NamedGroup>());
        assertTrue(chooser.getClientSupportedNamedGroups().isEmpty());

    }

    /**
     * Test of getServerSupportedPointFormats method, of class DefaultChooser.
     */
    @Test
    public void testGetServerSupportedPointFormats() {
        List<ECPointFormat> formatList = new LinkedList<>();
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        config.setDefaultServerSupportedPointFormats(formatList);
        assertTrue(config.getDefaultServerSupportedPointFormats().size() == 8);
        assertTrue(chooser.getServerSupportedPointFormats().size() == 8);
        context.setServerPointFormatsList(new LinkedList<ECPointFormat>());
        assertTrue(chooser.getServerSupportedPointFormats().isEmpty());
    }

    /**
     * Test of getClientSupportedSignatureAndHashAlgorithms method, of class
     * DefaultChooser.
     */
    @Test
    public void testGetClientSupportedSignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.DSA_MD5);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algoList);
        assertTrue(config.getDefaultClientSupportedSignatureAndHashAlgorithms().size() == 1);
        assertTrue(chooser.getClientSupportedSignatureAndHashAlgorithms().size() == 1);
        context.setClientSupportedSignatureAndHashAlgorithms(new LinkedList<SignatureAndHashAlgorithm>());
        assertTrue(chooser.getClientSupportedSignatureAndHashAlgorithms().isEmpty());
    }

    /**
     * Test of getClientSNIEntryList method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSNIEntryList() {
        List<SNIEntry> listSNI = new LinkedList<>();
        listSNI.add(new SNIEntry("Test", NameType.HOST_NAME));
        config.setDefaultClientSNIEntryList(listSNI);
        assertTrue(config.getDefaultClientSNIEntryList().size() == 1);
        assertTrue(chooser.getClientSNIEntryList().size() == 1);
        context.setClientSNIEntryList(new LinkedList<SNIEntry>());
        assertTrue(context.getClientSNIEntryList().isEmpty());
    }

    /**
     * Test of getLastRecordVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetLastRecordVersion() {
        config.setDefaultLastRecordProtocolVersion(ProtocolVersion.TLS13_DRAFT20);
        assertEquals(ProtocolVersion.TLS13_DRAFT20, config.getDefaultLastRecordProtocolVersion());
        assertEquals(ProtocolVersion.TLS13_DRAFT20, chooser.getLastRecordVersion());
        context.setLastRecordVersion(ProtocolVersion.SSL2);
        assertEquals(ProtocolVersion.SSL2, context.getLastRecordVersion());
    }

    /**
     * Test of getDistinguishedNames method, of class DefaultChooser.
     */
    @Test
    public void testGetDistinguishedNames() {
        byte[] namelist = { (byte) 0, (byte) 1 };
        config.setDistinguishedNames(namelist);
        assertTrue(config.getDistinguishedNames().length == 2);
        assertTrue(chooser.getDistinguishedNames().length == 2);
        byte[] namelist2 = { (byte) 0, (byte) 1, (byte) 3 };
        context.setDistinguishedNames(namelist2);
        assertTrue(chooser.getDistinguishedNames().length == 3);
    }

    /**
     * Test of getClientCertificateTypes method, of class DefaultChooser.
     */
    @Test
    public void testGetClientCertificateTypes() {
        List<ClientCertificateType> typeList = new LinkedList<>();
        typeList.add(ClientCertificateType.DSS_EPHEMERAL_DH_RESERVED);
        typeList.add(ClientCertificateType.DSS_FIXED_DH);
        typeList.add(ClientCertificateType.DSS_SIGN);
        typeList.add(ClientCertificateType.FORTEZZA_DMS_RESERVED);
        typeList.add(ClientCertificateType.RSA_EPHEMERAL_DH_RESERVED);
        typeList.add(ClientCertificateType.RSA_FIXED_DH);
        typeList.add(ClientCertificateType.RSA_SIGN);
        config.setClientCertificateTypes(typeList);
        assertTrue(config.getClientCertificateTypes().size() == 7);
        assertTrue(chooser.getClientCertificateTypes().size() == 7);
        context.setClientCertificateTypes(new LinkedList<ClientCertificateType>());
        assertTrue(chooser.getClientCertificateTypes().isEmpty());

    }

    /**
     * Test of getMaxFragmentLength method, of class DefaultChooser.
     */
    @Test
    public void testGetMaxFragmentLength() {
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_9);
        assertEquals(MaxFragmentLength.TWO_9, config.getMaxFragmentLength());
        assertEquals(MaxFragmentLength.TWO_9, chooser.getMaxFragmentLength());
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);
        assertEquals(MaxFragmentLength.TWO_11, chooser.getMaxFragmentLength());
    }

    /**
     * Test of getHeartbeatMode method, of class DefaultChooser.
     */
    @Test
    public void testGetHeartbeatMode() {
        config.setHeartbeatMode(HeartbeatMode.PEER_ALLOWED_TO_SEND);
        assertEquals(HeartbeatMode.PEER_ALLOWED_TO_SEND, config.getHeartbeatMode());
        assertEquals(HeartbeatMode.PEER_ALLOWED_TO_SEND, chooser.getHeartbeatMode());
        context.setHeartbeatMode(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND);
        assertEquals(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND, chooser.getHeartbeatMode());
    }

    /**
     * Test of isExtendedMasterSecretExtension method, of class DefaultChooser.
     */
    @Test
    public void testIsUseExtendedMasterSecret() {
        assertEquals(false, chooser.isUseExtendedMasterSecret());
        context.setUseExtendedMasterSecret(true);
        assertEquals(true, chooser.isUseExtendedMasterSecret());
    }

    /**
     * Test of getClientSupportedCompressions method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedCompressions() {
        LinkedList<CompressionMethod> clientSupportedCompressionMethods = new LinkedList<>();
        LinkedList<CompressionMethod> clientSupportedCompressionMethods2 = new LinkedList<>();
        clientSupportedCompressionMethods.add(CompressionMethod.LZS);
        clientSupportedCompressionMethods.add(CompressionMethod.NULL);
        clientSupportedCompressionMethods.add(CompressionMethod.DEFLATE);
        config.setDefaultClientSupportedCompressionMethods(clientSupportedCompressionMethods);
        assertEquals(clientSupportedCompressionMethods, config.getDefaultClientSupportedCompressionMethods());
        assertEquals(clientSupportedCompressionMethods, chooser.getClientSupportedCompressions());
        context.setClientSupportedCompressions(clientSupportedCompressionMethods2);
        assertEquals(clientSupportedCompressionMethods2, chooser.getClientSupportedCompressions());
    }

    /**
     * Test of getClientSupportedCiphersuites method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedCiphersuites() {
        LinkedList<CipherSuite> clientSupportedCiphersuites = new LinkedList<>();
        LinkedList<CipherSuite> clientSupportedCiphersuites2 = new LinkedList<>();
        clientSupportedCiphersuites.add(CipherSuite.TLS_FALLBACK_SCSV);
        clientSupportedCiphersuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        clientSupportedCiphersuites.add(CipherSuite.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA);
        clientSupportedCiphersuites.add(CipherSuite.SSL_FORTEZZA_KEA_WITH_NULL_SHA);
        clientSupportedCiphersuites.add(CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256);
        clientSupportedCiphersuites.add(CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384);
        config.setDefaultClientSupportedCiphersuites(clientSupportedCiphersuites);
        assertEquals(clientSupportedCiphersuites, config.getDefaultClientSupportedCiphersuites());
        assertEquals(clientSupportedCiphersuites, chooser.getClientSupportedCiphersuites());
        context.setClientSupportedCiphersuites(clientSupportedCiphersuites2);
        assertEquals(clientSupportedCiphersuites2, chooser.getClientSupportedCiphersuites());
    }

    /**
     * Test of getServerSupportedSignatureAndHashAlgorithms method, of class
     * DefaultChooser.
     */
    @Test
    public void testGetServerSupportedSignatureAndHashAlgorithms() {
        LinkedList<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms = new LinkedList<>();
        LinkedList<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms2 = new LinkedList<>();
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_MD5);
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA1);
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA256);
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA384);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(serverSupportedSignatureAndHashAlgorithms);
        assertEquals(serverSupportedSignatureAndHashAlgorithms,
                config.getDefaultServerSupportedSignatureAndHashAlgorithms());
        assertEquals(serverSupportedSignatureAndHashAlgorithms, chooser.getServerSupportedSignatureAndHashAlgorithms());
        context.setServerSupportedSignatureAndHashAlgorithms(serverSupportedSignatureAndHashAlgorithms2);
        assertEquals(serverSupportedSignatureAndHashAlgorithms2, chooser.getServerSupportedSignatureAndHashAlgorithms());
    }

    /**
     * Test of getSelectedProtocolVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedProtocolVersion() {
        context.setSelectedProtocolVersion(null);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13_DRAFT20);
        assertEquals(ProtocolVersion.TLS13_DRAFT20, config.getDefaultSelectedProtocolVersion());
        assertEquals(ProtocolVersion.TLS13_DRAFT20, chooser.getSelectedProtocolVersion());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        assertEquals(ProtocolVersion.TLS12, chooser.getSelectedProtocolVersion());
    }

    /**
     * Test of getHighestClientProtocolVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetHighestClientProtocolVersion() {
        context.setHighestClientProtocolVersion(null);
        config.setDefaultHighestClientProtocolVersion(ProtocolVersion.TLS10);
        assertEquals(ProtocolVersion.TLS10, config.getDefaultHighestClientProtocolVersion());
        assertEquals(ProtocolVersion.TLS10, chooser.getHighestClientProtocolVersion());
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS11);
        assertEquals(ProtocolVersion.TLS11, chooser.getHighestClientProtocolVersion());
    }

    /**
     * Test of getTalkingConnectionEnd method, of class DefaultChooser.
     */
    @Test
    public void testGetTalkingConnectionEnd() {
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        assertEquals(ConnectionEndType.CLIENT, chooser.getTalkingConnectionEnd());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        assertEquals(ConnectionEndType.SERVER, chooser.getTalkingConnectionEnd());
        context.setTalkingConnectionEndType(null);
        assertEquals(null, chooser.getTalkingConnectionEnd());
    }

    /**
     * Test of getMasterSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetMasterSecret() {
        byte[] masterSecret = ArrayConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultMasterSecret(masterSecret);
        assertArrayEquals(masterSecret, config.getDefaultMasterSecret());
        assertArrayEquals(masterSecret, chooser.getMasterSecret());
        context.setMasterSecret(masterSecret);
        assertArrayEquals(masterSecret, chooser.getMasterSecret());
    }

    /**
     * Test of getSelectedCipherSuite method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedCipherSuite() {
        context.setSelectedCipherSuite(null);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256);
        assertEquals(CipherSuite.TLS_AES_128_CCM_SHA256, config.getDefaultSelectedCipherSuite());
        assertEquals(CipherSuite.TLS_AES_128_CCM_SHA256, chooser.getSelectedCipherSuite());
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
        assertEquals(CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA, chooser.getSelectedCipherSuite());
    }

    /**
     * Test of getPreMasterSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetPreMasterSecret() {
        byte[] preMasterSecret = ArrayConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultPreMasterSecret(preMasterSecret);
        assertArrayEquals(preMasterSecret, config.getDefaultPreMasterSecret());
        assertArrayEquals(preMasterSecret, chooser.getPreMasterSecret());
        context.setPreMasterSecret(preMasterSecret);
        assertArrayEquals(preMasterSecret, chooser.getPreMasterSecret());
    }

    /**
     * Test of getClientRandom method, of class DefaultChooser.
     */
    @Test
    public void testGetClientRandom() {
        byte[] clientRandom = ArrayConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultClientRandom(clientRandom);
        assertArrayEquals(clientRandom, config.getDefaultClientRandom());
        assertArrayEquals(clientRandom, chooser.getClientRandom());
        context.setClientRandom(clientRandom);
        assertArrayEquals(clientRandom, chooser.getClientRandom());
    }

    /**
     * Test of getServerRandom method, of class DefaultChooser.
     */
    @Test
    public void testGetServerRandom() {
        byte[] serverRandom = ArrayConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultServerRandom(serverRandom);
        assertArrayEquals(serverRandom, config.getDefaultServerRandom());
        assertArrayEquals(serverRandom, chooser.getServerRandom());
        context.setServerRandom(serverRandom);
        assertArrayEquals(serverRandom, chooser.getServerRandom());
    }

    /**
     * Test of getSelectedCompressionMethod method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedCompressionMethod() {
        context.setSelectedCompressionMethod(null);
        config.setDefaultSelectedCompressionMethod(CompressionMethod.DEFLATE);
        assertEquals(CompressionMethod.DEFLATE, config.getDefaultSelectedCompressionMethod());
        assertEquals(CompressionMethod.DEFLATE, chooser.getSelectedCompressionMethod());
        context.setSelectedCompressionMethod(CompressionMethod.LZS);
        assertEquals(CompressionMethod.LZS, chooser.getSelectedCompressionMethod());
    }

    /**
     * Test of getClientSessionId method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSessionId() {
        byte[] sessionID = new byte[0];
        config.setDefaultClientSessionId(sessionID);
        assertArrayEquals(sessionID, config.getDefaultClientSessionId());
        assertArrayEquals(sessionID, chooser.getClientSessionId());
        context.setClientSessionId(sessionID);
        assertArrayEquals(sessionID, chooser.getClientSessionId());
    }

    /**
     * Test of getServerSessionId method, of class DefaultChooser.
     */
    @Test
    public void testGetServerSessionId() {
        byte[] sessionID = new byte[0];
        config.setDefaultServerSessionId(sessionID);
        assertArrayEquals(sessionID, config.getDefaultServerSessionId());
        assertArrayEquals(sessionID, chooser.getServerSessionId());
        context.setServerSessionId(sessionID);
        assertArrayEquals(sessionID, chooser.getServerSessionId());
    }

    /**
     * Test of getDtlsCookie method, of class DefaultChooser.
     */
    @Test
    public void testGetDtlsCookie() {
        byte[] cookie = ArrayConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDtlsDefaultCookie(cookie);
        assertArrayEquals(cookie, config.getDtlsDefaultCookie());
        assertArrayEquals(cookie, chooser.getDtlsCookie());
        context.setDtlsCookie(cookie);
        assertArrayEquals(cookie, chooser.getDtlsCookie());
    }

    /**
     * Test of getTransportHandler method, of class DefaultChooser.
     */
    @Test
    public void testGetTransportHandler() {
        TransportHandler transportHandler = new ClientTcpTransportHandler(0, "abc", 0);
        context.setTransportHandler(transportHandler);
        assertEquals(transportHandler, chooser.getTransportHandler());
    }

    /**
     * Test of getPRFAlgorithm method, of class DefaultChooser.
     */
    @Test
    public void testGetPRFAlgorithm() {
        context.setPrfAlgorithm(null);
        config.setDefaultPRFAlgorithm(PRFAlgorithm.TLS_PRF_SHA384);
        assertEquals(PRFAlgorithm.TLS_PRF_SHA384, config.getDefaultPRFAlgorithm());
        assertEquals(PRFAlgorithm.TLS_PRF_SHA384, chooser.getPRFAlgorithm());
        context.setPrfAlgorithm(PRFAlgorithm.TLS_PRF_SHA256);
        assertEquals(PRFAlgorithm.TLS_PRF_SHA256, chooser.getPRFAlgorithm());
    }

    /**
     * Test of getSessionTicketTLS method, of class DefaultChooser.
     */
    @Test
    public void testGetSessionTicketTLS() {
        context.setSessionTicketTLS(null);
        byte[] sessionTicketTLS = ArrayConverter.hexStringToByteArray("122131123987891238098123");
        byte[] sessionTicketTLS2 = ArrayConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setTlsSessionTicket(sessionTicketTLS);
        assertArrayEquals(sessionTicketTLS, config.getTlsSessionTicket());
        assertArrayEquals(sessionTicketTLS, chooser.getSessionTicketTLS());
        context.setSessionTicketTLS(sessionTicketTLS2);
        assertArrayEquals(sessionTicketTLS2, chooser.getSessionTicketTLS());
    }

    /**
     * Test of getSignedCertificateTimestamp method, of class DefaultChooser.
     */
    @Test
    public void testGetSignedCertificateTimestamp() {
        context.setSignedCertificateTimestamp(null);
        byte[] timestamp = ArrayConverter.hexStringToByteArray("122131123987891238098123");
        byte[] timestamp2 = ArrayConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultSignedCertificateTimestamp(timestamp);
        assertArrayEquals(timestamp, config.getDefaultSignedCertificateTimestamp());
        assertArrayEquals(timestamp, chooser.getSignedCertificateTimestamp());
        context.setSignedCertificateTimestamp(timestamp2);
        assertArrayEquals(timestamp2, chooser.getSignedCertificateTimestamp());
    }

    /**
     * Test of getTokenBindingVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetTokenBindingVersion() {
        context.setTokenBindingVersion(null);
        config.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_13);
        assertEquals(TokenBindingVersion.DRAFT_13, config.getDefaultTokenBindingVersion());
        assertEquals(TokenBindingVersion.DRAFT_13, chooser.getTokenBindingVersion());
        context.setTokenBindingVersion(TokenBindingVersion.DRAFT_1);
        assertEquals(TokenBindingVersion.DRAFT_1, chooser.getTokenBindingVersion());
    }

    /**
     * Test of getTokenBindingKeyParameters method, of class DefaultChooser.
     */
    @Test
    public void testGetTokenBindingKeyParameters() {
        List<TokenBindingKeyParameters> paramList = new LinkedList<>();
        List<TokenBindingKeyParameters> paramList2 = new LinkedList<>();
        paramList.add(TokenBindingKeyParameters.ECDSAP256);
        paramList.add(TokenBindingKeyParameters.RSA2048_PKCS1_5);
        paramList.add(TokenBindingKeyParameters.RSA2048_PSS);
        config.setDefaultTokenBindingKeyParameters(paramList);
        assertEquals(paramList, config.getDefaultTokenBindingKeyParameters());
        assertEquals(paramList, chooser.getTokenBindingKeyParameters());
        context.setTokenBindingKeyParameters(paramList2);
        assertEquals(paramList2, chooser.getTokenBindingKeyParameters());
    }

    /**
     * Test of getServerDhModulus method, of class DefaultChooser.
     */
    @Test
    public void testGetDhModulus() {
        context.setServerDhModulus(null);
        config.setDefaultServerDhModulus(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerDhModulus());
        assertEquals(BigInteger.ONE, chooser.getServerDhModulus());
        context.setServerDhModulus(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerDhModulus());
    }

    /**
     * Test of getServerDhGenerator method, of class DefaultChooser.
     */
    @Test
    public void testGetDhGenerator() {
        context.setServerDhGenerator(null);
        config.setDefaultServerDhGenerator(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerDhGenerator());
        assertEquals(BigInteger.ONE, chooser.getServerDhGenerator());
        context.setServerDhGenerator(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerDhGenerator());
    }

    /**
     * Test of getDhServerPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhServerPrivateKey() {
        context.setServerDhPrivateKey(null);
        config.setDefaultServerDhPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerDhPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getDhServerPrivateKey());
        context.setServerDhPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getDhServerPrivateKey());
    }

    /**
     * Test of getDhClientPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhClientPrivateKey() {
        context.setClientDhPrivateKey(null);
        config.setDefaultClientDhPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultClientDhPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getDhClientPrivateKey());
        context.setClientDhPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getDhClientPrivateKey());
    }

    /**
     * Test of getDhServerPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhServerPublicKey() {
        context.setServerDhPublicKey(null);
        config.setDefaultServerDhPublicKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerDhPublicKey());
        assertEquals(BigInteger.ONE, chooser.getDhServerPublicKey());
        context.setServerDhPublicKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getDhServerPublicKey());
    }

    /**
     * Test of getDhClientPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhClientPublicKey() {
        context.setClientDhPublicKey(null);
        config.setDefaultClientDhPublicKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultClientDhPublicKey());
        assertEquals(BigInteger.ONE, chooser.getDhClientPublicKey());
        context.setClientDhPublicKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getDhClientPublicKey());
    }

    /**
     * Test of getServerEcPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetServerEcPrivateKey() {
        context.setServerEcPrivateKey(null);
        config.setDefaultServerEcPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerEcPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getServerEcPrivateKey());
        context.setServerEcPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerEcPrivateKey());
    }

    /**
     * Test of getClientEcPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetClientEcPrivateKey() {
        context.setClientEcPrivateKey(null);
        config.setDefaultClientEcPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultClientEcPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getClientEcPrivateKey());
        context.setClientEcPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getClientEcPrivateKey());
    }

    /**
     * Test of getSelectedNamedGroup method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedCurve() {
        context.setSelectedGroup(null);
        config.setDefaultSelectedNamedGroup(NamedGroup.FFDHE2048);
        assertEquals(NamedGroup.FFDHE2048, config.getDefaultSelectedNamedGroup());
        assertEquals(NamedGroup.FFDHE2048, chooser.getSelectedNamedGroup());
        context.setSelectedGroup(NamedGroup.SECT163R1);
        assertEquals(NamedGroup.SECT163R1, chooser.getSelectedNamedGroup());
    }

    /**
     * Test of getClientEcPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetClientEcPublicKey() {
        context.setClientEcPublicKey(null);
        config.setDefaultClientEcPublicKey(Point.createPoint(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1));
        assertEquals(Point.createPoint(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1),
                config.getDefaultClientEcPublicKey());
        assertEquals(Point.createPoint(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1),
                chooser.getClientEcPublicKey());
        context.setClientEcPublicKey(Point.createPoint(BigInteger.ZERO, BigInteger.TEN, NamedGroup.SECP256R1));
        assertEquals(Point.createPoint(BigInteger.ZERO, BigInteger.TEN, NamedGroup.SECP256R1),
                chooser.getClientEcPublicKey());
    }

    /**
     * Test of getServerEcPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetServerEcPublicKey() {
        context.setServerEcPublicKey(null);
        config.setDefaultServerEcPublicKey(Point.createPoint(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1));
        assertEquals(Point.createPoint(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1),
                config.getDefaultServerEcPublicKey());
        assertEquals(Point.createPoint(BigInteger.ONE, BigInteger.TEN, NamedGroup.SECP256R1),
                chooser.getServerEcPublicKey());
        context.setServerEcPublicKey(Point.createPoint(BigInteger.ZERO, BigInteger.TEN, NamedGroup.SECP256R1));
        assertEquals(Point.createPoint(BigInteger.ZERO, BigInteger.TEN, NamedGroup.SECP256R1),
                chooser.getServerEcPublicKey());
    }

    /**
     * Test of getEcCurveType method, of class DefaultChooser.
     */
    @Test
    public void testGetEcCurveType() {
        assertEquals(EllipticCurveType.NAMED_CURVE, chooser.getEcCurveType());
    }

    /**
     * Test of getRsaModulus method, of class DefaultChooser.
     */
    @Test
    public void testGetRsaModulus() {
        context.setServerRsaModulus(null);
        config.setDefaultServerRSAModulus(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerRSAModulus());
        assertEquals(BigInteger.ONE, chooser.getServerRsaModulus());
        context.setServerRsaModulus(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerRsaModulus());
    }

    /**
     * Test of getServerRSAPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetServerRSAPublicKey() {
        context.setServerRSAPublicKey(null);
        config.setDefaultServerRSAPublicKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerRSAPublicKey());
        assertEquals(BigInteger.ONE, chooser.getServerRSAPublicKey());
        context.setServerRSAPublicKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerRSAPublicKey());
    }

    /**
     * Test of getClientRSAPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetClientRSAPublicKey() {
        context.setClientRSAPublicKey(null);
        config.setDefaultClientRSAPublicKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultClientRSAPublicKey());
        assertEquals(BigInteger.ONE, chooser.getClientRSAPublicKey());
        context.setClientRSAPublicKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getClientRSAPublicKey());
    }

    /**
     * Test of getCertificateRequestContext method, of class DefaultChooser.
     */
    @Test
    public void testGetCertificateRequestContext() {
        context.setCertificateRequestContext(null);
        byte[] requestContext = ArrayConverter.hexStringToByteArray("122131123987891238098123");
        byte[] requestContext2 = ArrayConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultCertificateRequestContext(requestContext);
        assertArrayEquals(requestContext, config.getDefaultCertificateRequestContext());
        assertArrayEquals(requestContext, chooser.getCertificateRequestContext());
        context.setCertificateRequestContext(requestContext2);
        assertArrayEquals(requestContext2, chooser.getCertificateRequestContext());
    }

    /**
     * Test of getServerHandshakeTrafficSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetServerHandshakeTrafficSecret() {
        context.setServerHandshakeTrafficSecret(null);
        byte[] secret = ArrayConverter.hexStringToByteArray("122131123987891238098123");
        byte[] secret2 = ArrayConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultServerHandshakeTrafficSecret(secret);
        assertArrayEquals(secret, config.getDefaultServerHandshakeTrafficSecret());
        assertArrayEquals(secret, chooser.getServerHandshakeTrafficSecret());
        context.setServerHandshakeTrafficSecret(secret2);
        assertArrayEquals(secret2, chooser.getServerHandshakeTrafficSecret());
    }

    /**
     * Test of getClientHandshakeTrafficSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetClientHandshakeTrafficSecret() {
        context.setClientHandshakeTrafficSecret(null);
        byte[] secret = ArrayConverter.hexStringToByteArray("122131123987891238098123");
        byte[] secret2 = ArrayConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultClientHandshakeTrafficSecret(secret);
        assertArrayEquals(secret, config.getDefaultClientHandshakeTrafficSecret());
        assertArrayEquals(secret, chooser.getClientHandshakeTrafficSecret());
        context.setClientHandshakeTrafficSecret(secret2);
        assertArrayEquals(secret2, chooser.getClientHandshakeTrafficSecret());
    }

    /**
     * Test of getPWDClientUsername method, of class DefaultChooser.
     */
    @Test
    public void testGetPWDClientUsername() {
        context.setClientPWDUsername(null);
        config.setDefaultClientPWDUsername("Jake");
        assertEquals("Jake", config.getDefaultClientPWDUsername());
        assertEquals("Jake", chooser.getClientPWDUsername());
        context.setClientPWDUsername("Brian");
        assertEquals("Brian", chooser.getClientPWDUsername());
    }

    /**
     * Test of getServerPWDSalt method, of class DefaultChooser.
     */
    @Test
    public void testGetServerPWDSalt() {
        byte[] salt = ArrayConverter.hexStringToByteArray("12");
        byte[] salt2 = ArrayConverter.hexStringToByteArray("FF");
        context.setServerPWDSalt(null);
        config.setDefaultServerPWDSalt(salt);
        assertEquals(salt, config.getDefaultServerPWDSalt());
        assertEquals(null, chooser.getServerPWDSalt());
        context.setServerPWDSalt(salt2);
        assertEquals(salt2, chooser.getServerPWDSalt());
    }

    /**
     * Test of getPWDPassword method, of class DefaultChooser.
     */
    @Test
    public void testGetPWDPassword() {
        config.setDefaultPWDPassword("Jake");
        assertEquals("Jake", chooser.getPWDPassword());
    }
}
