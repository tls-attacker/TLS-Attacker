/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.factory;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.*;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.*;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class HandlerFactoryTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
    }

    public static Stream<Arguments> provideGetHandlerTestVectors() {
        return Stream.of(
            Arguments.of(ProtocolMessageType.HANDSHAKE, HandshakeMessageType.UNKNOWN, UnknownHandshakeHandler.class),
            Arguments.of(ProtocolMessageType.CHANGE_CIPHER_SPEC, null, ChangeCipherSpecHandler.class),
            Arguments.of(ProtocolMessageType.ALERT, null, AlertHandler.class),
            Arguments.of(ProtocolMessageType.APPLICATION_DATA, null, ApplicationMessageHandler.class),
            Arguments.of(ProtocolMessageType.HEARTBEAT, null, HeartbeatMessageHandler.class),
            Arguments.of(ProtocolMessageType.UNKNOWN, null, UnknownMessageHandler.class));
    }

    @ParameterizedTest
    @MethodSource("provideGetHandlerTestVectors")
    public void getHandler(ProtocolMessageType providedProtocolMessageType,
        HandshakeMessageType providedHandshakeMessageType, Class<?> expectedHandlerClass) {
        assertTrue(expectedHandlerClass
            .isInstance(HandlerFactory.getHandler(context, providedProtocolMessageType, providedHandshakeMessageType)));
    }

    public static Stream<Arguments> provideGetHandshakeMessageHandlerTestVectors() {
        return Stream.of(Arguments.of(HandshakeMessageType.CERTIFICATE, CertificateMessageHandler.class),
            Arguments.of(HandshakeMessageType.CERTIFICATE_REQUEST, CertificateRequestHandler.class),
            Arguments.of(HandshakeMessageType.CERTIFICATE_VERIFY, CertificateVerifyHandler.class),
            Arguments.of(HandshakeMessageType.CLIENT_HELLO, ClientHelloHandler.class),
            Arguments.of(HandshakeMessageType.ENCRYPTED_EXTENSIONS, EncryptedExtensionsHandler.class),
            Arguments.of(HandshakeMessageType.END_OF_EARLY_DATA, EndOfEarlyDataHandler.class),
            Arguments.of(HandshakeMessageType.FINISHED, FinishedHandler.class),
            Arguments.of(HandshakeMessageType.HELLO_REQUEST, HelloRequestHandler.class),
            Arguments.of(HandshakeMessageType.HELLO_VERIFY_REQUEST, HelloVerifyRequestHandler.class),
            Arguments.of(HandshakeMessageType.NEW_SESSION_TICKET, NewSessionTicketHandler.class),
            Arguments.of(HandshakeMessageType.SERVER_HELLO, ServerHelloHandler.class),
            Arguments.of(HandshakeMessageType.SERVER_HELLO_DONE, ServerHelloDoneHandler.class),
            Arguments.of(HandshakeMessageType.UNKNOWN, UnknownHandshakeHandler.class));
    }

    @ParameterizedTest
    @MethodSource("provideGetHandshakeMessageHandlerTestVectors")
    public void testGetHandshakeMessageHandler(HandshakeMessageType providedHandshakeMessageType,
        Class<?> expectedHandlerClass) {
        assertTrue(
            expectedHandlerClass.isInstance(HandlerFactory.getHandshakeHandler(context, providedHandshakeMessageType)));
    }

    public static Stream<Arguments> provideGetExtensionHandlerTestVectors() {
        return Stream.of(Arguments.of(ExtensionType.ALPN, AlpnExtensionHandler.class),
            Arguments.of(ExtensionType.CACHED_INFO, CachedInfoExtensionHandler.class),
            Arguments.of(ExtensionType.CERT_TYPE, CertificateTypeExtensionHandler.class),
            Arguments.of(ExtensionType.CLIENT_AUTHZ, ClientAuthzExtensionHandler.class),
            Arguments.of(ExtensionType.CLIENT_CERTIFICATE_TYPE, ClientCertificateTypeExtensionHandler.class),
            Arguments.of(ExtensionType.CLIENT_CERTIFICATE_URL, ClientCertificateUrlExtensionHandler.class),
            Arguments.of(ExtensionType.EARLY_DATA, EarlyDataExtensionHandler.class),
            Arguments.of(ExtensionType.EC_POINT_FORMATS, EcPointFormatExtensionHandler.class),
            Arguments.of(ExtensionType.ELLIPTIC_CURVES, EllipticCurvesExtensionHandler.class),
            Arguments.of(ExtensionType.ENCRYPT_THEN_MAC, EncryptThenMacExtensionHandler.class),
            Arguments.of(ExtensionType.EXTENDED_MASTER_SECRET, ExtendedMasterSecretExtensionHandler.class),
            Arguments.of(ExtensionType.HEARTBEAT, HeartbeatExtensionHandler.class),
            Arguments.of(ExtensionType.KEY_SHARE_OLD, KeyShareExtensionHandler.class),
            Arguments.of(ExtensionType.KEY_SHARE, KeyShareExtensionHandler.class),
            Arguments.of(ExtensionType.MAX_FRAGMENT_LENGTH, MaxFragmentLengthExtensionHandler.class),
            Arguments.of(ExtensionType.PADDING, PaddingExtensionHandler.class),
            Arguments.of(ExtensionType.PRE_SHARED_KEY, PreSharedKeyExtensionHandler.class),
            Arguments.of(ExtensionType.PSK_KEY_EXCHANGE_MODES, PSKKeyExchangeModesExtensionHandler.class),
            Arguments.of(ExtensionType.RENEGOTIATION_INFO, RenegotiationInfoExtensionHandler.class),
            Arguments.of(ExtensionType.SERVER_AUTHZ, ServerAuthzExtensionHandler.class),
            Arguments.of(ExtensionType.SERVER_CERTIFICATE_TYPE, ServerCertificateTypeExtensionHandler.class),
            Arguments.of(ExtensionType.SERVER_NAME_INDICATION, ServerNameIndicationExtensionHandler.class),
            Arguments.of(ExtensionType.SESSION_TICKET, SessionTicketTlsExtensionHandler.class),
            Arguments.of(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithmsExtensionHandler.class),
            Arguments.of(ExtensionType.SIGNATURE_ALGORITHMS_CERT, SignatureAlgorithmsCertExtensionHandler.class),
            Arguments.of(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP, SignedCertificateTimestampExtensionHandler.class),
            Arguments.of(ExtensionType.SRP, SrpExtensionHandler.class),
            Arguments.of(ExtensionType.STATUS_REQUEST, CertificateStatusRequestExtensionHandler.class),
            Arguments.of(ExtensionType.STATUS_REQUEST_V2, CertificateStatusRequestV2ExtensionHandler.class),
            Arguments.of(ExtensionType.SUPPORTED_VERSIONS, SupportedVersionsExtensionHandler.class),
            Arguments.of(ExtensionType.TOKEN_BINDING, TokenBindingExtensionHandler.class),
            Arguments.of(ExtensionType.TRUNCATED_HMAC, TruncatedHmacExtensionHandler.class),
            Arguments.of(ExtensionType.TRUSTED_CA_KEYS, TrustedCaIndicationExtensionHandler.class),
            Arguments.of(ExtensionType.UNKNOWN, UnknownExtensionHandler.class),
            Arguments.of(ExtensionType.USER_MAPPING, UserMappingExtensionHandler.class),
            Arguments.of(ExtensionType.USE_SRTP, SrtpExtensionHandler.class),
            Arguments.of(ExtensionType.PWD_PROTECT, PWDProtectExtensionHandler.class),
            Arguments.of(ExtensionType.PWD_CLEAR, PWDClearExtensionHandler.class),
            Arguments.of(ExtensionType.PASSWORD_SALT, PasswordSaltExtensionHandler.class),
            Arguments.of(ExtensionType.EXTENDED_RANDOM, ExtendedRandomExtensionHandler.class),
            Arguments.of(ExtensionType.COOKIE, CookieExtensionHandler.class));
    }

    @ParameterizedTest
    @MethodSource("provideGetExtensionHandlerTestVectors")
    public void getExtensionHandler(ExtensionType providedExtensionType, Class<?> expectedHandlerClass) {
        assertTrue(expectedHandlerClass.isInstance(HandlerFactory.getExtensionHandler(context, providedExtensionType)));
    }

    public static Stream<Arguments> provideGetKeyExchangeHandlerTestVectors() {
        return Stream.of(
            Arguments.of(CipherSuite.TLS_RSA_WITH_NULL_MD5, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                RSAClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                ECDHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                ECDHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                ECDHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                ECDHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                DHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                DHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                DHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                DHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                DHClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                PskDhClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                PskEcDhClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                PskRsaClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_PSK_WITH_NULL_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                PskClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                SrpClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                SrpClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                SrpClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                GOSTClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                GOSTClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256, HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                PWDClientKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                ECDHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                ECDHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                ECDHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                ECDHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                DHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                DHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                DHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                DHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                DHEServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                PskDheServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                PskEcDheServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_PSK_WITH_NULL_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                PskServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                SrpServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                SrpServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                SrpServerKeyExchangeHandler.class),
            Arguments.of(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256, HandshakeMessageType.SERVER_KEY_EXCHANGE,
                PWDServerKeyExchangeHandler.class));
    }

    @ParameterizedTest
    @MethodSource("provideGetKeyExchangeHandlerTestVectors")
    public void getKeyExchangeHandler(CipherSuite providedCipherSuite,
        HandshakeMessageType providedHandshakeMessageType, Class<?> expectedHandlerClass) {
        context.setSelectedCipherSuite(providedCipherSuite);
        assertTrue(
            expectedHandlerClass.isInstance(HandlerFactory.getHandshakeHandler(context, providedHandshakeMessageType)));
    }
}
