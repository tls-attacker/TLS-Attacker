/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.factory;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.*;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.*;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class HandlerFactoryTest {

    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
    }

    @Test
    public void getHandler() {
        assertTrue(HandlerFactory.getHandler(context, ProtocolMessageType.HANDSHAKE, HandshakeMessageType.UNKNOWN) instanceof UnknownHandshakeHandler);
        assertTrue(HandlerFactory.getHandler(context, ProtocolMessageType.CHANGE_CIPHER_SPEC, null) instanceof ChangeCipherSpecHandler);
        assertTrue(HandlerFactory.getHandler(context, ProtocolMessageType.ALERT, null) instanceof AlertHandler);
        assertTrue(HandlerFactory.getHandler(context, ProtocolMessageType.APPLICATION_DATA, null) instanceof ApplicationMessageHandler);
        assertTrue(HandlerFactory.getHandler(context, ProtocolMessageType.HEARTBEAT, null) instanceof HeartbeatMessageHandler);
        assertTrue(HandlerFactory.getHandler(context, ProtocolMessageType.UNKNOWN, null) instanceof UnknownHandler);
    }

    @Test
    public void getHandshakeHandler() {
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CERTIFICATE) instanceof CertificateMessageHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CERTIFICATE_REQUEST) instanceof CertificateRequestHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CERTIFICATE_VERIFY) instanceof CertificateVerifyHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_HELLO) instanceof ClientHelloHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.ENCRYPTED_EXTENSIONS) instanceof EncryptedExtensionsHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.END_OF_EARLY_DATA) instanceof EndOfEarlyDataHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.FINISHED) instanceof FinishedHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.HELLO_RETRY_REQUEST) instanceof HelloRetryRequestHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.HELLO_REQUEST) instanceof HelloRequestHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.HELLO_VERIFY_REQUEST) instanceof HelloVerifyRequestHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.NEW_SESSION_TICKET) instanceof NewSessionTicketHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_HELLO) instanceof ServerHelloHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_HELLO_DONE) instanceof ServerHelloDoneHandler);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.UNKNOWN) instanceof UnknownHandshakeHandler);
    }

    @Test
    public void getExtensionHandler() {
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.ALPN, null) instanceof AlpnExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.CACHED_INFO, null) instanceof CachedInfoExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.CERT_TYPE, null) instanceof CertificateTypeExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.CLIENT_AUTHZ, null) instanceof ClientAuthzExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.CLIENT_CERTIFICATE_TYPE, null) instanceof ClientCertificateTypeExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.CLIENT_CERTIFICATE_URL, null) instanceof ClientCertificateUrlExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.EARLY_DATA, null) instanceof EarlyDataExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.EC_POINT_FORMATS, null) instanceof EcPointFormatExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.ELLIPTIC_CURVES, null) instanceof EllipticCurvesExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.ENCRYPT_THEN_MAC, null) instanceof EncryptThenMacExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.EXTENDED_MASTER_SECRET, null) instanceof ExtendedMasterSecretExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.HEARTBEAT, null) instanceof HeartbeatExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.KEY_SHARE_OLD,
                HandshakeMessageType.HELLO_RETRY_REQUEST) instanceof HrrKeyShareExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.KEY_SHARE,
                HandshakeMessageType.HELLO_RETRY_REQUEST) instanceof HrrKeyShareExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.KEY_SHARE_OLD, null) instanceof KeyShareExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.KEY_SHARE, null) instanceof KeyShareExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.MAX_FRAGMENT_LENGTH, null) instanceof MaxFragmentLengthExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.PADDING, null) instanceof PaddingExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.PRE_SHARED_KEY, null) instanceof PreSharedKeyExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.PSK_KEY_EXCHANGE_MODES, null) instanceof PSKKeyExchangeModesExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.RENEGOTIATION_INFO, null) instanceof RenegotiationInfoExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SERVER_AUTHZ, null) instanceof ServerAuthzExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SERVER_CERTIFICATE_TYPE, null) instanceof ServerCertificateTypeExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SERVER_NAME_INDICATION, null) instanceof ServerNameIndicationExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SESSION_TICKET, null) instanceof SessionTicketTlsExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS, null) instanceof SignatureAndHashAlgorithmsExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP, null) instanceof SignedCertificateTimestampExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SRP, null) instanceof SrpExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.STATUS_REQUEST, null) instanceof CertificateStatusRequestExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.STATUS_REQUEST_V2, null) instanceof CertificateStatusRequestV2ExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.SUPPORTED_VERSIONS, null) instanceof SupportedVersionsExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.TOKEN_BINDING, null) instanceof TokenBindingExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.TRUNCATED_HMAC, null) instanceof TruncatedHmacExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.TRUSTED_CA_KEYS, null) instanceof TrustedCaIndicationExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.UNKNOWN, null) instanceof UnknownExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.USER_MAPPING, null) instanceof UserMappingExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.USE_SRTP, null) instanceof SrtpExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.PWD_PROTECT, null) instanceof PWDProtectExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.PWD_CLEAR, null) instanceof PWDClearExtensionHandler);
        assertTrue(HandlerFactory.getExtensionHandler(context, ExtensionType.PASSWORD_SALT, null) instanceof PasswordSaltExtensionHandler);
    }

    @Test
    public void getClientKeyExchangeHandler() {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_NULL_MD5);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof RSAClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof ECDHClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof ECDHClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof ECDHClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof ECDHClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof DHClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof DHClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof DHClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof DHClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof DHClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof PskDhClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof PskEcDhClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof PskRsaClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof PskClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof SrpClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof SrpClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof SrpClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_GOSTR341001_WITH_28147_CNT_IMIT);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof GOSTClientKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof GOSTClientKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.CLIENT_KEY_EXCHANGE) instanceof PWDClientKeyExchangeHandler);
    }

    @Test
    public void getServerKeyExchangeHandler() {
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof ECDHEServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof ECDHEServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof ECDHEServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof ECDHEServerKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof DHEServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof DHEServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof DHEServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof DHEServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof DHEServerKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof PskDheServerKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof PskEcDheServerKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_NULL_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof PskServerKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof SrpServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof SrpServerKeyExchangeHandler);
        context.setSelectedCipherSuite(CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof SrpServerKeyExchangeHandler);

        context.setSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        assertTrue(HandlerFactory.getHandshakeHandler(context, HandshakeMessageType.SERVER_KEY_EXCHANGE) instanceof PWDServerKeyExchangeHandler);
    }
}
