/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.session.Session;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DefaultChooserTest {

    private Chooser chooser;
    private TlsContext context;
    private Config config;

    @BeforeEach
    public void setUp() {
        context = new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        chooser = context.getChooser();
        config = chooser.getConfig();
    }

    /** Test of getClientSupportedPointFormats method, of class DefaultChooser. */
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
        assertEquals(8, config.getDefaultClientSupportedPointFormats().size());
        assertEquals(8, chooser.getClientSupportedPointFormats().size());
        context.setClientPointFormatsList(new LinkedList<>());
        assertTrue(chooser.getClientSupportedPointFormats().isEmpty());
    }

    /** Test of getSelectedSigHashAlgorithm method, of class DefaultChooser. */
    @Test
    public void testGetSelectedSigHashAlgorithm() {
        config.setDefaultSelectedSignatureAndHashAlgorithm(
                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        assertEquals(
                config.getDefaultSelectedSignatureAndHashAlgorithm(),
                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        assertEquals(
                chooser.getSelectedSigHashAlgorithm(),
                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        context.setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.DSA_SHA1);
        assertEquals(chooser.getSelectedSigHashAlgorithm(), SignatureAndHashAlgorithm.DSA_SHA1);
    }

    /** Test of getClientSupportedNamedGroups method, of class DefaultChooser. */
    @Test
    public void testGetClientSupportedNamedCurves() {
        List<NamedGroup> curveList = new LinkedList<>();
        curveList.add(NamedGroup.BRAINPOOLP256R1);
        curveList.add(NamedGroup.ECDH_X448);
        curveList.add(NamedGroup.SECP160K1);
        config.setDefaultClientNamedGroups(curveList);
        assertEquals(3, config.getDefaultClientNamedGroups().size());
        assertEquals(3, chooser.getClientSupportedNamedGroups().size());
        context.setClientNamedGroupsList(new LinkedList<>());
        assertTrue(chooser.getClientSupportedNamedGroups().isEmpty());
    }

    /** Test of getServerSupportedPointFormats method, of class DefaultChooser. */
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
        assertEquals(8, config.getDefaultServerSupportedPointFormats().size());
        assertEquals(8, chooser.getServerSupportedPointFormats().size());
        context.setServerPointFormatsList(new LinkedList<>());
        assertTrue(chooser.getServerSupportedPointFormats().isEmpty());
    }

    /** Test of getClientSupportedSignatureAndHashAlgorithms method, of class DefaultChooser. */
    @Test
    public void testGetClientSupportedSignatureAndHashAlgorithms() {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        algoList.add(SignatureAndHashAlgorithm.DSA_MD5);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algoList);
        assertEquals(1, config.getDefaultClientSupportedSignatureAndHashAlgorithms().size());
        assertEquals(1, chooser.getClientSupportedSignatureAndHashAlgorithms().size());
        context.setClientSupportedSignatureAndHashAlgorithms(new LinkedList<>());
        assertTrue(chooser.getClientSupportedSignatureAndHashAlgorithms().isEmpty());
    }

    /** Test of getLastRecordVersion method, of class DefaultChooser. */
    @Test
    public void testGetLastRecordVersion() {
        config.setDefaultLastRecordProtocolVersion(ProtocolVersion.TLS13_DRAFT20);
        assertEquals(ProtocolVersion.TLS13_DRAFT20, config.getDefaultLastRecordProtocolVersion());
        assertEquals(ProtocolVersion.TLS13_DRAFT20, chooser.getLastRecordVersion());
        context.setLastRecordVersion(ProtocolVersion.SSL2);
        assertEquals(ProtocolVersion.SSL2, context.getLastRecordVersion());
    }

    /** Test of getDistinguishedNames method, of class DefaultChooser. */
    @Test
    public void testGetDistinguishedNames() {
        byte[] namelist = {(byte) 0, (byte) 1};
        config.setDistinguishedNames(namelist);
        assertEquals(2, config.getDistinguishedNames().length);
        assertEquals(2, chooser.getDistinguishedNames().length);
        byte[] namelist2 = {(byte) 0, (byte) 1, (byte) 3};
        context.setDistinguishedNames(namelist2);
        assertEquals(3, chooser.getDistinguishedNames().length);
    }

    /** Test of getClientCertificateTypes method, of class DefaultChooser. */
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
        assertEquals(7, config.getClientCertificateTypes().size());
        assertEquals(7, chooser.getClientCertificateTypes().size());
        context.setClientCertificateTypes(new LinkedList<>());
        assertTrue(chooser.getClientCertificateTypes().isEmpty());
    }

    /** Test of getHeartbeatMode method, of class DefaultChooser. */
    @Test
    public void testGetHeartbeatMode() {
        config.setHeartbeatMode(HeartbeatMode.PEER_ALLOWED_TO_SEND);
        assertEquals(HeartbeatMode.PEER_ALLOWED_TO_SEND, config.getHeartbeatMode());
        assertEquals(HeartbeatMode.PEER_ALLOWED_TO_SEND, chooser.getHeartbeatMode());
        context.setHeartbeatMode(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND);
        assertEquals(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND, chooser.getHeartbeatMode());
    }

    /** Test of isExtendedMasterSecretExtension method, of class DefaultChooser. */
    @Test
    public void testIsUseExtendedMasterSecret() {
        assertFalse(chooser.isUseExtendedMasterSecret());
        context.setUseExtendedMasterSecret(true);
        assertTrue(chooser.isUseExtendedMasterSecret());
    }

    /** Test of getClientSupportedCompressions method, of class DefaultChooser. */
    @Test
    public void testGetClientSupportedCompressions() {
        LinkedList<CompressionMethod> clientSupportedCompressionMethods = new LinkedList<>();
        LinkedList<CompressionMethod> clientSupportedCompressionMethods2 = new LinkedList<>();
        clientSupportedCompressionMethods.add(CompressionMethod.LZS);
        clientSupportedCompressionMethods.add(CompressionMethod.NULL);
        clientSupportedCompressionMethods.add(CompressionMethod.DEFLATE);
        config.setDefaultClientSupportedCompressionMethods(clientSupportedCompressionMethods);
        assertEquals(
                clientSupportedCompressionMethods,
                config.getDefaultClientSupportedCompressionMethods());
        assertEquals(clientSupportedCompressionMethods, chooser.getClientSupportedCompressions());
        context.setClientSupportedCompressions(clientSupportedCompressionMethods2);
        assertEquals(clientSupportedCompressionMethods2, chooser.getClientSupportedCompressions());
    }

    /** Test of getClientSupportedCiphersuites method, of class DefaultChooser. */
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
        config.setDefaultClientSupportedCipherSuites(clientSupportedCiphersuites);
        assertEquals(clientSupportedCiphersuites, config.getDefaultClientSupportedCipherSuites());
        assertEquals(clientSupportedCiphersuites, chooser.getClientSupportedCipherSuites());
        context.setClientSupportedCipherSuites(clientSupportedCiphersuites2);
        assertEquals(clientSupportedCiphersuites2, chooser.getClientSupportedCipherSuites());
    }

    /** Test of getServerSupportedSignatureAndHashAlgorithms method, of class DefaultChooser. */
    @Test
    public void testGetServerSupportedSignatureAndHashAlgorithms() {
        LinkedList<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms =
                new LinkedList<>();
        LinkedList<SignatureAndHashAlgorithm> serverSupportedSignatureAndHashAlgorithms2 =
                new LinkedList<>();
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_MD5);
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA1);
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA256);
        serverSupportedSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA384);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSupportedSignatureAndHashAlgorithms);
        assertEquals(
                serverSupportedSignatureAndHashAlgorithms,
                config.getDefaultServerSupportedSignatureAndHashAlgorithms());
        assertEquals(
                serverSupportedSignatureAndHashAlgorithms,
                chooser.getServerSupportedSignatureAndHashAlgorithms());
        context.setServerSupportedSignatureAndHashAlgorithms(
                serverSupportedSignatureAndHashAlgorithms2);
        assertEquals(
                serverSupportedSignatureAndHashAlgorithms2,
                chooser.getServerSupportedSignatureAndHashAlgorithms());
    }

    /** Test of getSelectedProtocolVersion method, of class DefaultChooser. */
    @Test
    public void testGetSelectedProtocolVersion() {
        context.setSelectedProtocolVersion(null);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13_DRAFT20);
        assertEquals(ProtocolVersion.TLS13_DRAFT20, config.getDefaultSelectedProtocolVersion());
        assertEquals(ProtocolVersion.TLS13_DRAFT20, chooser.getSelectedProtocolVersion());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        assertEquals(ProtocolVersion.TLS12, chooser.getSelectedProtocolVersion());
    }

    /** Test of getHighestClientProtocolVersion method, of class DefaultChooser. */
    @Test
    public void testGetHighestClientProtocolVersion() {
        context.setHighestClientProtocolVersion(null);
        config.setDefaultHighestClientProtocolVersion(ProtocolVersion.TLS10);
        assertEquals(ProtocolVersion.TLS10, config.getDefaultHighestClientProtocolVersion());
        assertEquals(ProtocolVersion.TLS10, chooser.getHighestClientProtocolVersion());
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS11);
        assertEquals(ProtocolVersion.TLS11, chooser.getHighestClientProtocolVersion());
    }

    /** Test of getTalkingConnectionEnd method, of class DefaultChooser. */
    @Test
    public void testGetTalkingConnectionEnd() {
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        assertEquals(ConnectionEndType.CLIENT, chooser.getTalkingConnectionEnd());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        assertEquals(ConnectionEndType.SERVER, chooser.getTalkingConnectionEnd());
        context.setTalkingConnectionEndType(null);
        assertNull(chooser.getTalkingConnectionEnd());
    }

    /** Test of getMasterSecret method, of class DefaultChooser. */
    @Test
    public void testGetMasterSecret() {
        byte[] masterSecret =
                DataConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultMasterSecret(masterSecret);
        assertArrayEquals(masterSecret, config.getDefaultMasterSecret());
        assertArrayEquals(masterSecret, chooser.getMasterSecret());
        context.setMasterSecret(masterSecret);
        assertArrayEquals(masterSecret, chooser.getMasterSecret());
    }

    /** Test of getSelectedCipherSuite method, of class DefaultChooser. */
    @Test
    public void testGetSelectedCipherSuite() {
        context.setSelectedCipherSuite(null);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_CCM_SHA256);
        assertEquals(CipherSuite.TLS_AES_128_CCM_SHA256, config.getDefaultSelectedCipherSuite());
        assertEquals(CipherSuite.TLS_AES_128_CCM_SHA256, chooser.getSelectedCipherSuite());
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
        assertEquals(
                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
                chooser.getSelectedCipherSuite());
    }

    /** Test of getPreMasterSecret method, of class DefaultChooser. */
    @Test
    public void testGetPreMasterSecret() {
        byte[] preMasterSecret =
                DataConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultPreMasterSecret(preMasterSecret);
        assertArrayEquals(preMasterSecret, config.getDefaultPreMasterSecret());
        assertArrayEquals(preMasterSecret, chooser.getPreMasterSecret());
        context.setPreMasterSecret(preMasterSecret);
        assertArrayEquals(preMasterSecret, chooser.getPreMasterSecret());
    }

    /** Test of getClientRandom method, of class DefaultChooser. */
    @Test
    public void testGetClientRandom() {
        byte[] clientRandom =
                DataConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultClientRandom(clientRandom);
        assertArrayEquals(clientRandom, config.getDefaultClientRandom());
        assertArrayEquals(clientRandom, chooser.getClientRandom());
        context.setClientRandom(clientRandom);
        assertArrayEquals(clientRandom, chooser.getClientRandom());
    }

    /** Test of getServerRandom method, of class DefaultChooser. */
    @Test
    public void testGetServerRandom() {
        byte[] serverRandom =
                DataConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDefaultServerRandom(serverRandom);
        assertArrayEquals(serverRandom, config.getDefaultServerRandom());
        assertArrayEquals(serverRandom, chooser.getServerRandom());
        context.setServerRandom(serverRandom);
        assertArrayEquals(serverRandom, chooser.getServerRandom());
    }

    /** Test of getClientExtendedRandom method of class DefaultChooser. */
    @Test
    public void testGetClientExtendedRandom() {
        byte[] clientExtendedRandom = DataConverter.hexStringToByteArray("abcd");
        config.setDefaultClientExtendedRandom(clientExtendedRandom);
        assertArrayEquals(clientExtendedRandom, config.getDefaultClientExtendedRandom());
        assertArrayEquals(clientExtendedRandom, chooser.getClientExtendedRandom());
        context.setClientExtendedRandom(clientExtendedRandom);
        assertArrayEquals(clientExtendedRandom, chooser.getClientExtendedRandom());
    }

    /** Test of getServerExtendedRandom of class DefaultChooser. */
    @Test
    public void testGetServerExtendedRandom() {
        byte[] serverExtendedRandom = DataConverter.hexStringToByteArray("abcd");
        config.setDefaultServerExtendedRandom(serverExtendedRandom);
        assertArrayEquals(serverExtendedRandom, config.getDefaultServerExtendedRandom());
        assertArrayEquals(serverExtendedRandom, chooser.getServerExtendedRandom());
        context.setServerExtendedRandom(serverExtendedRandom);
        assertArrayEquals(serverExtendedRandom, chooser.getServerExtendedRandom());
    }

    /** Test of getSelectedCompressionMethod method, of class DefaultChooser. */
    @Test
    public void testGetSelectedCompressionMethod() {
        context.setSelectedCompressionMethod(null);
        config.setDefaultSelectedCompressionMethod(CompressionMethod.DEFLATE);
        assertEquals(CompressionMethod.DEFLATE, config.getDefaultSelectedCompressionMethod());
        assertEquals(CompressionMethod.DEFLATE, chooser.getSelectedCompressionMethod());
        context.setSelectedCompressionMethod(CompressionMethod.LZS);
        assertEquals(CompressionMethod.LZS, chooser.getSelectedCompressionMethod());
    }

    /** Test of getClientSessionId method, of class DefaultChooser. */
    @Test
    public void testGetClientSessionId() {
        byte[] sessionID = new byte[0];
        config.setDefaultClientSessionId(sessionID);
        assertArrayEquals(sessionID, config.getDefaultClientSessionId());
        assertArrayEquals(sessionID, chooser.getClientSessionId());
        context.setClientSessionId(sessionID);
        assertArrayEquals(sessionID, chooser.getClientSessionId());
    }

    /** Test of getServerSessionId method, of class DefaultChooser. */
    @Test
    public void testGetServerSessionId() {
        byte[] sessionID = new byte[0];
        config.setDefaultServerSessionId(sessionID);
        assertArrayEquals(sessionID, config.getDefaultServerSessionId());
        assertArrayEquals(sessionID, chooser.getServerSessionId());
        context.setServerSessionId(sessionID);
        assertArrayEquals(sessionID, chooser.getServerSessionId());
    }

    /** Test of getDtlsCookie method, of class DefaultChooser. */
    @Test
    public void testGetDtlsCookie() {
        byte[] cookie = DataConverter.hexStringToByteArray("ab18712378669892893619236899692136");
        config.setDtlsDefaultCookie(cookie);
        assertArrayEquals(cookie, config.getDtlsDefaultCookie());
        assertArrayEquals(cookie, chooser.getDtlsCookie());
        context.setDtlsCookie(cookie);
        assertArrayEquals(cookie, chooser.getDtlsCookie());
    }

    /** Test of getTransportHandler method, of class DefaultChooser. */
    @Test
    public void testGetTransportHandler() {
        TransportHandler transportHandler = new ClientTcpTransportHandler(0, 0, "abc", 0);
        context.setTransportHandler(transportHandler);
        assertEquals(transportHandler, chooser.getTransportHandler());
    }

    /** Test of getPRFAlgorithm method, of class DefaultChooser. */
    @Test
    public void testGetPRFAlgorithm() {
        context.setPrfAlgorithm(null);
        config.setDefaultPRFAlgorithm(PRFAlgorithm.TLS_PRF_SHA384);
        assertEquals(PRFAlgorithm.TLS_PRF_SHA384, config.getDefaultPRFAlgorithm());
        assertEquals(PRFAlgorithm.TLS_PRF_SHA384, chooser.getPRFAlgorithm());
        context.setPrfAlgorithm(PRFAlgorithm.TLS_PRF_SHA256);
        assertEquals(PRFAlgorithm.TLS_PRF_SHA256, chooser.getPRFAlgorithm());
    }

    /** Test of getLatestSessionTicket method, of class DefaultChooser. */
    @Test
    public void testGetLatestSessionTicket() {
        List<Session> sessionList = new LinkedList<>();
        context.setSessionList(sessionList);
        byte[] sessionTicketTLS = DataConverter.hexStringToByteArray("122131123987891238098123");
        byte[] sessionTicketTLS2 =
                DataConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setTlsSessionTicket(sessionTicketTLS);
        assertArrayEquals(sessionTicketTLS, config.getTlsSessionTicket());
        assertArrayEquals(sessionTicketTLS, chooser.getLatestSessionTicket());
        TicketSession session =
                new TicketSession(config.getDefaultMasterSecret(), sessionTicketTLS2);
        context.addNewSession(session);
        assertArrayEquals(sessionTicketTLS2, chooser.getLatestSessionTicket());
    }

    /** Test of getSignedCertificateTimestamp method, of class DefaultChooser. */
    @Test
    public void testGetSignedCertificateTimestamp() {
        context.setSignedCertificateTimestamp(null);
        byte[] timestamp = DataConverter.hexStringToByteArray("122131123987891238098123");
        byte[] timestamp2 = DataConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultSignedCertificateTimestamp(timestamp);
        assertArrayEquals(timestamp, config.getDefaultSignedCertificateTimestamp());
        assertArrayEquals(timestamp, chooser.getSignedCertificateTimestamp());
        context.setSignedCertificateTimestamp(timestamp2);
        assertArrayEquals(timestamp2, chooser.getSignedCertificateTimestamp());
    }

    /** Test of getTokenBindingVersion method, of class DefaultChooser. */
    @Test
    public void testGetTokenBindingVersion() {
        context.setTokenBindingVersion(null);
        config.setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_13);
        assertEquals(TokenBindingVersion.DRAFT_13, config.getDefaultTokenBindingVersion());
        assertEquals(TokenBindingVersion.DRAFT_13, chooser.getTokenBindingVersion());
        context.setTokenBindingVersion(TokenBindingVersion.DRAFT_1);
        assertEquals(TokenBindingVersion.DRAFT_1, chooser.getTokenBindingVersion());
    }

    /** Test of getTokenBindingKeyParameters method, of class DefaultChooser. */
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

    /** Test of getServerDhModulus method, of class DefaultChooser. */
    @Test
    public void testGetDhModulus() {
        context.setServerEphemeralDhModulus(null);
        config.setDefaultServerEphemeralDhModulus(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerEphemeralDhModulus());
        assertEquals(BigInteger.ONE, chooser.getServerEphemeralDhModulus());
        context.setServerEphemeralDhModulus(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerEphemeralDhModulus());
    }

    /** Test of getServerDhGenerator method, of class DefaultChooser. */
    @Test
    public void testGetDhGenerator() {
        context.setServerEphemeralDhGenerator(null);
        config.setDefaultServerEphemeralDhGenerator(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerEphemeralDhGenerator());
        assertEquals(BigInteger.ONE, chooser.getServerEphemeralDhGenerator());
        context.setServerEphemeralDhGenerator(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerEphemeralDhGenerator());
    }

    /** Test of getDhServerPrivateKey method, of class DefaultChooser. */
    @Test
    public void testGetDhServerPrivateKey() {
        context.setServerEphemeralDhPrivateKey(null);
        config.setDefaultServerEphemeralDhPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerEphemeralDhPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getServerEphemeralDhPrivateKey());
        context.setServerEphemeralDhPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerEphemeralDhPrivateKey());
    }

    /** Test of getDhClientPrivateKey method, of class DefaultChooser. */
    @Test
    public void testGetDhClientPrivateKey() {
        context.setClientEphemeralDhPrivateKey(null);
        config.setDefaultClientEphemeralDhPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultClientEphemeralDhPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getClientEphemeralDhPrivateKey());
        context.setClientEphemeralDhPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getClientEphemeralDhPrivateKey());
    }

    /** Test of getDhServerPublicKey method, of class DefaultChooser. */
    @Test
    public void testGetDhServerPublicKey() {
        context.setServerEphemeralDhPublicKey(null);
        config.setDefaultServerEphemeralDhPublicKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerEphemeralDhPublicKey());
        assertEquals(BigInteger.ONE, chooser.getServerEphemeralDhPublicKey());
        context.setServerEphemeralDhPublicKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerEphemeralDhPublicKey());
    }

    /** Test of getDhClientPublicKey method, of class DefaultChooser. */
    @Test
    public void testGetDhClientPublicKey() {
        context.setClientEphemeralDhPublicKey(null);
        config.setDefaultClientEphemeralDhPublicKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultClientEphemeralDhPublicKey());
        assertEquals(BigInteger.ONE, chooser.getClientEphemeralDhPublicKey());
        context.setClientEphemeralDhPublicKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getClientEphemeralDhPublicKey());
    }

    /** Test of getServerEcPrivateKey method, of class DefaultChooser. */
    @Test
    public void testGetServerEcPrivateKey() {
        context.setServerEphemeralEcPrivateKey(null);
        config.setDefaultServerEphemeralEcPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultServerEphemeralEcPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getServerEphemeralEcPrivateKey());
        context.setServerEphemeralEcPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getServerEphemeralEcPrivateKey());
    }

    /** Test of getClientEcPrivateKey method, of class DefaultChooser. */
    @Test
    public void testGetClientEcPrivateKey() {
        context.setClientEphemeralEcPrivateKey(null);
        config.setDefaultClientEphemeralEcPrivateKey(BigInteger.ONE);
        assertEquals(BigInteger.ONE, config.getDefaultClientEphemeralEcPrivateKey());
        assertEquals(BigInteger.ONE, chooser.getClientEphemeralEcPrivateKey());
        context.setClientEphemeralEcPrivateKey(BigInteger.TEN);
        assertEquals(BigInteger.TEN, chooser.getClientEphemeralEcPrivateKey());
    }

    /** Test of getSelectedNamedGroup method, of class DefaultChooser. */
    @Test
    public void testGetSelectedCurve() {
        context.setSelectedGroup(null);
        config.setDefaultSelectedNamedGroup(NamedGroup.FFDHE2048);
        assertEquals(NamedGroup.FFDHE2048, config.getDefaultSelectedNamedGroup());
        assertEquals(NamedGroup.FFDHE2048, chooser.getSelectedNamedGroup());
        context.setSelectedGroup(NamedGroup.SECT163R1);
        assertEquals(NamedGroup.SECT163R1, chooser.getSelectedNamedGroup());
    }

    /** Test of getClientEcPublicKey method, of class DefaultChooser. */
    @Test
    public void testGetClientEcPublicKey() {
        context.setClientEphemeralEcPublicKey(null);
        config.setDefaultClientEphemeralEcPublicKey(
                Point.createPoint(
                        BigInteger.ONE,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()));
        assertEquals(
                Point.createPoint(
                        BigInteger.ONE,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()),
                config.getDefaultClientEphemeralEcPublicKey());
        assertEquals(
                Point.createPoint(
                        BigInteger.ONE,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()),
                chooser.getClientEphemeralEcPublicKey());
        context.setClientEphemeralEcPublicKey(
                Point.createPoint(
                        BigInteger.ZERO,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()));
        assertEquals(
                Point.createPoint(
                        BigInteger.ZERO,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()),
                chooser.getClientEphemeralEcPublicKey());
    }

    /** Test of getServerEcPublicKey method, of class DefaultChooser. */
    @Test
    public void testGetServerEcPublicKey() {
        context.setServerEphemeralEcPublicKey(null);
        config.setDefaultServerEphemeralEcPublicKey(
                Point.createPoint(
                        BigInteger.ONE,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()));
        assertEquals(
                Point.createPoint(
                        BigInteger.ONE,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()),
                config.getDefaultServerEphemeralEcPublicKey());
        assertEquals(
                Point.createPoint(
                        BigInteger.ONE,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()),
                chooser.getServerEphemeralEcPublicKey());
        context.setServerEphemeralEcPublicKey(
                Point.createPoint(
                        BigInteger.ZERO,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()));
        assertEquals(
                Point.createPoint(
                        BigInteger.ZERO,
                        BigInteger.TEN,
                        (NamedEllipticCurveParameters) NamedGroup.SECP256R1.getGroupParameters()),
                chooser.getServerEphemeralEcPublicKey());
    }

    /** Test of getEcCurveType method, of class DefaultChooser. */
    @Test
    public void testGetEcCurveType() {
        assertEquals(EllipticCurveType.NAMED_CURVE, chooser.getEcCurveType());
    }

    /** Test of getCertificateRequestContext method, of class DefaultChooser. */
    @Test
    public void testGetCertificateRequestContext() {
        context.setCertificateRequestContext(null);
        byte[] requestContext = DataConverter.hexStringToByteArray("122131123987891238098123");
        byte[] requestContext2 = DataConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultCertificateRequestContext(requestContext);
        assertArrayEquals(requestContext, config.getDefaultCertificateRequestContext());
        assertArrayEquals(requestContext, chooser.getCertificateRequestContext());
        context.setCertificateRequestContext(requestContext2);
        assertArrayEquals(requestContext2, chooser.getCertificateRequestContext());
    }

    /** Test of getServerHandshakeTrafficSecret method, of class DefaultChooser. */
    @Test
    public void testGetServerHandshakeTrafficSecret() {
        context.setServerHandshakeTrafficSecret(null);
        byte[] secret = DataConverter.hexStringToByteArray("122131123987891238098123");
        byte[] secret2 = DataConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultServerHandshakeTrafficSecret(secret);
        assertArrayEquals(secret, config.getDefaultServerHandshakeTrafficSecret());
        assertArrayEquals(secret, chooser.getServerHandshakeTrafficSecret());
        context.setServerHandshakeTrafficSecret(secret2);
        assertArrayEquals(secret2, chooser.getServerHandshakeTrafficSecret());
    }

    /** Test of getClientHandshakeTrafficSecret method, of class DefaultChooser. */
    @Test
    public void testGetClientHandshakeTrafficSecret() {
        context.setClientHandshakeTrafficSecret(null);
        byte[] secret = DataConverter.hexStringToByteArray("122131123987891238098123");
        byte[] secret2 = DataConverter.hexStringToByteArray("1221311239878912380981281294");
        config.setDefaultClientHandshakeTrafficSecret(secret);
        assertArrayEquals(secret, config.getDefaultClientHandshakeTrafficSecret());
        assertArrayEquals(secret, chooser.getClientHandshakeTrafficSecret());
        context.setClientHandshakeTrafficSecret(secret2);
        assertArrayEquals(secret2, chooser.getClientHandshakeTrafficSecret());
    }

    /** Test of getPWDClientUsername method, of class DefaultChooser. */
    @Test
    public void testGetPWDClientUsername() {
        context.setClientPWDUsername(null);
        config.setDefaultClientPWDUsername("Jake");
        assertEquals("Jake", config.getDefaultClientPWDUsername());
        assertEquals("Jake", chooser.getClientPWDUsername());
        context.setClientPWDUsername("Brian");
        assertEquals("Brian", chooser.getClientPWDUsername());
    }

    /** Test of getServerPWDSalt method, of class DefaultChooser. */
    @Test
    public void testGetServerPWDSalt() {
        byte[] salt = DataConverter.hexStringToByteArray("12");
        byte[] salt2 = DataConverter.hexStringToByteArray("FF");
        context.setServerPWDSalt(null);
        config.setDefaultServerPWDSalt(salt);
        assertArrayEquals(salt, config.getDefaultServerPWDSalt());
        assertArrayEquals(salt, chooser.getServerPWDSalt());
        context.setServerPWDSalt(salt2);
        assertArrayEquals(salt2, chooser.getServerPWDSalt());
    }

    /** Test of getPWDPassword method, of class DefaultChooser. */
    @Test
    public void testGetPWDPassword() {
        config.setDefaultPWDPassword("Jake");
        assertEquals("Jake", chooser.getPWDPassword());
    }
}
