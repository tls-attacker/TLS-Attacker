/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.layer.context.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.bouncycastle.util.Arrays;

public class DefaultChooser extends Chooser {

    private final HttpContext httpContext;
    private final TlsContext tlsContext;
    private final TcpContext tcpContext;

    DefaultChooser(Context context, Config config) {
        super(context, config);
        httpContext = context.getHttpContext();
        tlsContext = context.getTlsContext();
        tcpContext = context.getTcpContext();
    }

    @Override
    public CertificateType getSelectedClientCertificateType() {
        if (tlsContext.getSelectedClientCertificateType() != null) {
            return tlsContext.getSelectedClientCertificateType();
        } else {
            return config.getDefaultSelectedClientCertificateType();
        }
    }

    @Override
    public CertificateType getSelectedServerCertificateType() {
        if (tlsContext.getSelectedServerCertificateType() != null) {
            return tlsContext.getSelectedServerCertificateType();
        } else {
            return config.getDefaultSelectedServerCertificateType();
        }
    }

    @Override
    public List<ECPointFormat> getClientSupportedPointFormats() {
        if (tlsContext.getClientPointFormatsList() != null) {
            return tlsContext.getClientPointFormatsList();
        } else {
            return config.getDefaultClientSupportedPointFormats();
        }
    }

    @Override
    public SignatureAndHashAlgorithm getSelectedSigHashAlgorithm() {
        if (tlsContext.getSelectedSignatureAndHashAlgorithm() != null) {
            return tlsContext.getSelectedSignatureAndHashAlgorithm();
        } else {
            return config.getDefaultSelectedSignatureAndHashAlgorithm();
        }
    }

    @Override
    public List<NamedGroup> getClientSupportedNamedGroups() {
        if (tlsContext.getClientNamedGroupsList() != null) {
            return tlsContext.getClientNamedGroupsList();
        } else {
            return config.getDefaultClientNamedGroups();
        }
    }

    @Override
    public List<NamedGroup> getServerSupportedNamedGroups() {
        if (tlsContext.getServerNamedGroupsList() != null) {
            return tlsContext.getServerNamedGroupsList();
        } else {
            return config.getDefaultServerNamedGroups();
        }
    }

    @Override
    public List<ECPointFormat> getServerSupportedPointFormats() {
        if (tlsContext.getServerPointFormatsList() != null) {
            return tlsContext.getServerPointFormatsList();
        } else {
            return config.getDefaultServerSupportedPointFormats();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
        if (tlsContext.getClientSupportedSignatureAndHashAlgorithms() != null) {
            return tlsContext.getClientSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultClientSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public ProtocolVersion getLastRecordVersion() {
        if (tlsContext.getLastRecordVersion() != null) {
            return tlsContext.getLastRecordVersion();
        } else {
            return config.getDefaultLastRecordProtocolVersion();
        }
    }

    @Override
    public byte[] getDistinguishedNames() {
        if (tlsContext.getDistinguishedNames() != null) {
            return copy(tlsContext.getDistinguishedNames());
        } else {
            return config.getDistinguishedNames();
        }
    }

    @Override
    public List<ClientCertificateType> getClientCertificateTypes() {
        if (tlsContext.getClientCertificateTypes() != null) {
            return tlsContext.getClientCertificateTypes();
        } else {
            return config.getClientCertificateTypes();
        }
    }

    @Override
    public MaxFragmentLength getMaxFragmentLength() {
        if (tlsContext.getMaxFragmentLength() != null) {
            return tlsContext.getMaxFragmentLength();
        } else {
            return config.getDefaultMaxFragmentLength();
        }
    }

    @Override
    public HeartbeatMode getHeartbeatMode() {
        if (tlsContext.getHeartbeatMode() != null) {
            return tlsContext.getHeartbeatMode();
        } else {
            return config.getDefaultHeartbeatMode();
        }
    }

    @Override
    public boolean isUseExtendedMasterSecret() {
        return tlsContext.isUseExtendedMasterSecret();
    }

    @Override
    public List<CompressionMethod> getClientSupportedCompressions() {
        if (tlsContext.getClientSupportedCompressions() != null) {
            return tlsContext.getClientSupportedCompressions();
        } else {
            return config.getDefaultClientSupportedCompressionMethods();
        }
    }

    @Override
    public List<CipherSuite> getClientSupportedCipherSuites() {
        if (tlsContext.getClientSupportedCipherSuites() != null) {
            return tlsContext.getClientSupportedCipherSuites();
        } else {
            return config.getDefaultClientSupportedCipherSuites();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms() {
        if (tlsContext.getServerSupportedSignatureAndHashAlgorithms() != null) {
            return tlsContext.getServerSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultServerSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public ProtocolVersion getSelectedProtocolVersion() {
        if (tlsContext.getSelectedProtocolVersion() != null) {
            return tlsContext.getSelectedProtocolVersion();
        } else {
            return config.getDefaultSelectedProtocolVersion();
        }
    }

    @Override
    public ProtocolVersion getHighestClientProtocolVersion() {
        if (tlsContext.getHighestClientProtocolVersion() != null) {
            return tlsContext.getHighestClientProtocolVersion();
        } else {
            return config.getDefaultHighestClientProtocolVersion();
        }
    }

    @Override
    public ConnectionEndType getTalkingConnectionEnd() {
        return tlsContext.getTalkingConnectionEndType();
    }

    @Override
    public byte[] getMasterSecret() {
        if (tlsContext.getMasterSecret() != null) {
            return copy(tlsContext.getMasterSecret());
        } else {
            return config.getDefaultMasterSecret();
        }
    }

    @Override
    public CipherSuite getSelectedCipherSuite() {
        if (tlsContext.getSelectedCipherSuite() != null) {
            return tlsContext.getSelectedCipherSuite();
        } else {
            return config.getDefaultSelectedCipherSuite();
        }
    }

    @Override
    public SSL2CipherSuite getSSL2CipherSuite() {
        if (tlsContext.getSSL2CipherSuite() != null) {
            return tlsContext.getSSL2CipherSuite();
        } else {
            return config.getDefaultSSL2CipherSuite();
        }
    }

    @Override
    public byte[] getPreMasterSecret() {
        if (tlsContext.getPreMasterSecret() != null) {
            return copy(tlsContext.getPreMasterSecret());
        } else {
            return config.getDefaultPreMasterSecret();
        }
    }

    /**
     * Additional Check for Extended Random. If extended Random was negotiated, we add the additional bytes to the
     * Client Random
     */
    @Override
    public byte[] getClientRandom() {
        if (tlsContext.getClientRandom() != null) {
            return copy(tlsContext.getClientRandom());
        } else {
            return config.getDefaultClientRandom();
        }
    }

    @Override
    public byte[] getClientExtendedRandom() {
        if (tlsContext.getClientExtendedRandom() != null) {
            return copy(tlsContext.getClientExtendedRandom());
        } else {
            return config.getDefaultClientExtendedRandom();
        }
    }

    @Override
    public byte[] getServerExtendedRandom() {
        if (tlsContext.getServerExtendedRandom() != null) {
            return copy(tlsContext.getServerExtendedRandom());
        } else {
            return config.getDefaultServerExtendedRandom();
        }
    }

    /**
     * Additional Check for Extended Random.If extended Random was negotiated, we add the additional bytes to the Server
     * Random
     * 
     * @return
     */
    @Override
    public byte[] getServerRandom() {
        if (tlsContext.getServerRandom() != null) {
            return copy(tlsContext.getServerRandom());
        } else {
            return config.getDefaultServerRandom();
        }
    }

    @Override
    public CompressionMethod getSelectedCompressionMethod() {
        if (tlsContext.getSelectedCompressionMethod() != null) {
            return tlsContext.getSelectedCompressionMethod();
        } else {
            return config.getDefaultSelectedCompressionMethod();
        }
    }

    @Override
    public byte[] getClientSessionId() {
        if (tlsContext.getClientSessionId() != null) {
            return copy(tlsContext.getClientSessionId());
        } else {
            return config.getDefaultClientSessionId();
        }
    }

    @Override
    public byte[] getServerSessionId() {
        if (tlsContext.getServerSessionId() != null) {
            return copy(tlsContext.getServerSessionId());
        } else {
            return config.getDefaultServerSessionId();
        }
    }

    @Override
    public byte[] getDtlsCookie() {
        if (tlsContext.getDtlsCookie() != null) {
            return copy(tlsContext.getDtlsCookie());
        } else {
            return config.getDtlsDefaultCookie();
        }
    }

    @Override
    public TransportHandler getTransportHandler() {
        return tcpContext.getTransportHandler();
    }

    @Override
    public PRFAlgorithm getPRFAlgorithm() {
        if (tlsContext.getPrfAlgorithm() != null) {
            return tlsContext.getPrfAlgorithm();
        } else {
            return config.getDefaultPRFAlgorithm();
        }
    }

    @Override
    public byte[] getLatestSessionTicket() {
        if (tlsContext.getLatestSessionTicket() != null) {
            return tlsContext.getLatestSessionTicket();
        } else {
            return config.getTlsSessionTicket();
        }
    }

    @Override
    public byte[] getSignedCertificateTimestamp() {
        if (tlsContext.getSignedCertificateTimestamp() != null) {
            return copy(tlsContext.getSignedCertificateTimestamp());
        } else {
            return config.getDefaultSignedCertificateTimestamp();
        }
    }

    @Override
    public TokenBindingVersion getTokenBindingVersion() {
        if (tlsContext.getTokenBindingVersion() != null) {
            return tlsContext.getTokenBindingVersion();
        } else {
            return config.getDefaultTokenBindingVersion();
        }
    }

    @Override
    public List<TokenBindingKeyParameters> getTokenBindingKeyParameters() {
        if (tlsContext.getTokenBindingKeyParameters() != null) {
            return tlsContext.getTokenBindingKeyParameters();
        } else {
            return config.getDefaultTokenBindingKeyParameters();
        }
    }

    @Override
    public BigInteger getServerDhModulus() {
        if (tlsContext.getServerDhModulus() != null) {
            return tlsContext.getServerDhModulus();
        } else {
            return config.getDefaultServerDhModulus();
        }
    }

    @Override
    public BigInteger getServerDhGenerator() {
        if (tlsContext.getServerDhGenerator() != null) {
            return tlsContext.getServerDhGenerator();
        } else {
            return config.getDefaultServerDhGenerator();
        }
    }

    @Override
    public BigInteger getClientDhModulus() {
        if (tlsContext.getClientDhModulus() != null) {
            return tlsContext.getClientDhModulus();
        } else {
            return config.getDefaultClientDhModulus();
        }
    }

    @Override
    public BigInteger getClientDhGenerator() {
        if (tlsContext.getClientDhGenerator() != null) {
            return tlsContext.getClientDhGenerator();
        } else {
            return config.getDefaultClientDhGenerator();
        }
    }

    @Override
    public BigInteger getServerDhPrivateKey() {
        if (tlsContext.getServerDhPrivateKey() != null) {
            return tlsContext.getServerDhPrivateKey();
        } else {
            return config.getDefaultServerDhPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPModulus() {
        if (tlsContext.getSRPModulus() != null) {
            return tlsContext.getSRPModulus();
        } else {
            return config.getDefaultSRPModulus();
        }
    }

    @Override
    public byte[] getPSKIdentity() {
        if (tlsContext.getPSKIdentity() != null) {
            return copy(tlsContext.getPSKIdentity());
        } else {
            return config.getDefaultPSKIdentity();
        }
    }

    @Override
    public byte[] getPSKIdentityHint() {
        if (tlsContext.getPSKIdentityHint() != null) {
            return copy(tlsContext.getPSKIdentityHint());
        } else {
            return config.getDefaultPSKIdentityHint();
        }
    }

    @Override
    public BigInteger getPSKModulus() {
        if (tlsContext.getPSKModulus() != null) {
            return tlsContext.getPSKModulus();
        } else {
            return config.getDefaultPSKModulus();
        }
    }

    @Override
    public BigInteger getPSKServerPrivateKey() {
        if (tlsContext.getServerPSKPrivateKey() != null) {
            return tlsContext.getServerPSKPrivateKey();
        } else {
            return config.getDefaultPSKServerPrivateKey();
        }
    }

    @Override
    public BigInteger getPSKServerPublicKey() {
        if (tlsContext.getServerPSKPublicKey() != null) {
            return tlsContext.getServerPSKPublicKey();
        } else {
            return config.getDefaultPSKServerPublicKey();
        }
    }

    @Override
    public BigInteger getPSKGenerator() {
        if (tlsContext.getPSKGenerator() != null) {
            return tlsContext.getPSKGenerator();
        } else {
            return config.getDefaultPSKGenerator();
        }
    }

    @Override
    public BigInteger getSRPGenerator() {
        if (tlsContext.getSRPGenerator() != null) {
            return tlsContext.getSRPGenerator();
        } else {
            return config.getDefaultSRPGenerator();
        }
    }

    @Override
    public BigInteger getSRPServerPrivateKey() {
        if (tlsContext.getServerSRPPrivateKey() != null) {
            return tlsContext.getServerSRPPrivateKey();
        } else {
            return config.getDefaultSRPServerPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPServerPublicKey() {
        if (tlsContext.getServerSRPPublicKey() != null) {
            return tlsContext.getServerSRPPublicKey();
        } else {
            return config.getDefaultSRPServerPublicKey();
        }
    }

    @Override
    public BigInteger getSRPClientPrivateKey() {
        if (tlsContext.getClientSRPPrivateKey() != null) {
            return tlsContext.getClientSRPPrivateKey();
        } else {
            return config.getDefaultSRPClientPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPClientPublicKey() {
        if (tlsContext.getClientSRPPublicKey() != null) {
            return tlsContext.getClientSRPPublicKey();
        } else {
            return config.getDefaultSRPClientPublicKey();
        }
    }

    @Override
    public byte[] getSRPPassword() {
        if (tlsContext.getSRPPassword() != null) {
            return copy(tlsContext.getSRPPassword());
        } else {
            return config.getDefaultSRPPassword();
        }
    }

    @Override
    public byte[] getSRPIdentity() {
        if (tlsContext.getSRPIdentity() != null) {
            return copy(tlsContext.getSRPIdentity());
        } else {
            return config.getDefaultSRPIdentity();
        }
    }

    @Override
    public byte[] getSRPServerSalt() {
        if (tlsContext.getSRPServerSalt() != null) {
            return copy(tlsContext.getSRPServerSalt());
        } else {
            return config.getDefaultSRPServerSalt();
        }
    }

    @Override
    public BigInteger getClientDhPrivateKey() {
        if (tlsContext.getClientDhPrivateKey() != null) {
            return tlsContext.getClientDhPrivateKey();
        } else {
            return config.getDefaultClientDhPrivateKey();
        }
    }

    @Override
    public BigInteger getServerDhPublicKey() {
        if (tlsContext.getServerDhPublicKey() != null) {
            return tlsContext.getServerDhPublicKey();
        } else {
            return config.getDefaultServerDhPublicKey();
        }
    }

    @Override
    public BigInteger getClientDhPublicKey() {
        if (tlsContext.getClientDhPublicKey() != null) {
            return tlsContext.getClientDhPublicKey();
        } else {
            return config.getDefaultClientDhPublicKey();
        }
    }

    @Override
    public BigInteger getServerEcPrivateKey() {
        if (tlsContext.getServerEcPrivateKey() != null) {
            return tlsContext.getServerEcPrivateKey();
        } else {
            return config.getDefaultServerEcPrivateKey();
        }
    }

    @Override
    public GOSTCurve getSelectedGostCurve() {
        if (tlsContext.getSelectedGostCurve() != null) {
            return tlsContext.getSelectedGostCurve();
        } else {
            return config.getDefaultSelectedGostCurve();
        }
    }

    @Override
    public BigInteger getClientEcPrivateKey() {
        if (tlsContext.getClientEcPrivateKey() != null) {
            return tlsContext.getClientEcPrivateKey();
        } else {
            return config.getDefaultClientEcPrivateKey();
        }
    }

    @Override
    public NamedGroup getSelectedNamedGroup() {
        if (tlsContext.getSelectedGroup() != null) {
            return tlsContext.getSelectedGroup();
        } else {
            return config.getDefaultSelectedNamedGroup();
        }
    }

    @Override
    public NamedGroup getEcCertificateCurve() {
        if (tlsContext.getEcCertificateCurve() != null) {
            return tlsContext.getEcCertificateCurve();
        } else {
            return config.getDefaultEcCertificateCurve();
        }
    }

    @Override
    public Point getClientEcPublicKey() {
        if (tlsContext.getClientEcPublicKey() != null) {
            return tlsContext.getClientEcPublicKey();
        } else {
            return config.getDefaultClientEcPublicKey();
        }
    }

    @Override
    public Point getServerEcPublicKey() {
        if (tlsContext.getServerEcPublicKey() != null) {
            return tlsContext.getServerEcPublicKey();
        } else {
            return config.getDefaultServerEcPublicKey();
        }
    }

    @Override
    public EllipticCurveType getEcCurveType() {
        // We currently only support named curves TODO
        return EllipticCurveType.NAMED_CURVE;
    }

    @Override
    public BigInteger getServerRsaModulus() {
        if (tlsContext.getServerRSAModulus() != null) {
            return tlsContext.getServerRSAModulus();
        } else {
            return config.getDefaultServerRSAModulus();
        }
    }

    @Override
    public BigInteger getClientRsaModulus() {
        if (tlsContext.getClientRsaModulus() != null) {
            return tlsContext.getClientRsaModulus();
        } else {
            return config.getDefaultClientRSAModulus();
        }
    }

    @Override
    public BigInteger getServerRSAPublicKey() {
        if (tlsContext.getServerRSAPublicKey() != null) {
            return tlsContext.getServerRSAPublicKey();
        } else {
            return config.getDefaultServerRSAPublicKey();
        }
    }

    @Override
    public BigInteger getClientRSAPublicKey() {
        if (tlsContext.getClientRSAPublicKey() != null) {
            return tlsContext.getClientRSAPublicKey();
        } else {
            return config.getDefaultClientRSAPublicKey();
        }
    }

    @Override
    public byte[] getCertificateRequestContext() {
        if (tlsContext.getCertificateRequestContext() != null) {
            return copy(tlsContext.getCertificateRequestContext());
        } else {
            return config.getDefaultCertificateRequestContext();
        }
    }

    @Override
    public byte[] getServerHandshakeTrafficSecret() {
        if (tlsContext.getServerHandshakeTrafficSecret() != null) {
            return copy(tlsContext.getServerHandshakeTrafficSecret());
        } else {
            return config.getDefaultServerHandshakeTrafficSecret();
        }
    }

    @Override
    public byte[] getClientHandshakeTrafficSecret() {
        if (tlsContext.getClientHandshakeTrafficSecret() != null) {
            return copy(tlsContext.getClientHandshakeTrafficSecret());
        } else {
            return config.getDefaultClientHandshakeTrafficSecret();
        }
    }

    @Override
    public byte[] getClientApplicationTrafficSecret() {
        if (tlsContext.getClientApplicationTrafficSecret() != null) {
            return copy(tlsContext.getClientApplicationTrafficSecret());
        } else {
            return config.getDefaultClientApplicationTrafficSecret();
        }

    }

    @Override
    public byte[] getServerApplicationTrafficSecret() {
        if (tlsContext.getServerApplicationTrafficSecret() != null) {
            return copy(tlsContext.getServerApplicationTrafficSecret());
        } else {
            return config.getDefaultServerApplicationTrafficSecret();
        }
    }

    @Override
    public BigInteger getClientRSAPrivateKey() {
        if (tlsContext.getClientRSAPrivateKey() != null) {
            return tlsContext.getClientRSAPrivateKey();
        } else {
            return config.getDefaultClientRSAPrivateKey();
        }
    }

    @Override
    public BigInteger getServerRSAPrivateKey() {
        if (tlsContext.getServerRSAPrivateKey() != null) {
            return tlsContext.getServerRSAPrivateKey();
        } else {
            return config.getDefaultServerRSAPrivateKey();
        }
    }

    @Override
    public Connection getConnection() {
        return context.getConnection();
    }

    @Override
    public ConnectionEndType getMyConnectionPeer() {
        return getConnection().getLocalConnectionEndType() == ConnectionEndType.CLIENT ? ConnectionEndType.SERVER
            : ConnectionEndType.CLIENT;
    }

    @Override
    public ProtocolVersion getHighestProtocolVersion() {
        if (tlsContext.getHighestProtocolVersion() != null) {
            return tlsContext.getHighestProtocolVersion();
        } else {
            return config.getHighestProtocolVersion();
        }
    }

    @Override
    public boolean isClientAuthentication() {
        if (tlsContext.isClientAuthentication() != null) {
            return tlsContext.isClientAuthentication();
        } else {
            return config.isClientAuthentication();
        }
    }

    @Override
    public byte[] getLastHandledApplicationMessageData() {
        if (tlsContext.getLastHandledApplicationMessageData() != null) {
            return copy(tlsContext.getLastHandledApplicationMessageData());
        } else {
            return config.getDefaultApplicationMessageData().getBytes(StandardCharsets.ISO_8859_1);
        }
    }

    @Override
    public byte[] getPsk() {
        if (tlsContext.getPsk() != null) {
            return copy(tlsContext.getPsk());
        } else {
            return config.getPsk();
        }
    }

    @Override
    public String getHttpsCookieValue() {
        String cookieVal = tlsContext.getHttpsCookieValue();
        if (cookieVal != null && !cookieVal.isEmpty()) {
            return cookieVal;
        } else {
            return config.getDefaultHttpsCookieValue();
        }
    }

    @Override
    public String getHttpsCookieName() {
        String cookieName = tlsContext.getHttpsCookieName();
        if (cookieName != null && !cookieName.isEmpty()) {
            return cookieName;
        } else {
            return config.getDefaultHttpsCookieName();
        }
    }

    @Override
    public List<PskSet> getPskSets() {
        if (tlsContext.getPskSets() != null) {
            return tlsContext.getPskSets();
        } else {
            return config.getDefaultPskSets();
        }
    }

    @Override
    public CipherSuite getEarlyDataCipherSuite() {
        if (tlsContext.getEarlyDataCipherSuite() != null) {
            return tlsContext.getEarlyDataCipherSuite();
        } else {
            return config.getEarlyDataCipherSuite();
        }
    }

    @Override
    public byte[] getClientEarlyTrafficSecret() {
        if (tlsContext.getClientEarlyTrafficSecret() != null) {
            return copy(tlsContext.getClientEarlyTrafficSecret());
        } else {
            return config.getClientEarlyTrafficSecret();
        }
    }

    @Override
    public byte[] getEarlySecret() {
        if (tlsContext.getEarlySecret() != null) {
            return copy(tlsContext.getEarlySecret());
        } else {
            return config.getEarlySecret();
        }
    }

    @Override
    public byte[] getEarlyDataPsk() {
        if (tlsContext.getEarlyDataPsk() != null) {
            return copy(tlsContext.getEarlyDataPsk());
        } else {
            return config.getEarlyDataPsk();
        }
    }

    @Override
    public ConnectionEndType getConnectionEndType() {
        return getConnection().getLocalConnectionEndType();
    }

    @Override
    public List<KeyShareStoreEntry> getClientKeyShares() {
        if (tlsContext.getClientKeyShareStoreEntryList() != null) {
            return tlsContext.getClientKeyShareStoreEntryList();
        } else {
            return config.getDefaultClientKeyStoreEntries();
        }
    }

    @Override
    public KeyShareStoreEntry getServerKeyShare() {
        if (tlsContext.getServerKeyShareStoreEntry() != null) {
            return tlsContext.getServerKeyShareStoreEntry();
        } else {
            return config.getDefaultServerKeyShareEntry();
        }
    }

    @Override
    public BigInteger getDsaClientPrivateKey() {
        if (tlsContext.getClientDsaPrivateKey() != null) {
            return tlsContext.getClientDsaPrivateKey();
        } else {
            return config.getDefaultClientDsaPrivateKey();
        }
    }

    @Override
    public BigInteger getDsaClientPublicKey() {
        if (tlsContext.getClientDsaPublicKey() != null) {
            return tlsContext.getClientDsaPublicKey();
        } else {
            return config.getDefaultClientDsaPublicKey();
        }
    }

    @Override
    public BigInteger getDsaClientPrimeP() {
        if (tlsContext.getClientDsaPrimeP() != null) {
            return tlsContext.getClientDsaPrimeP();
        } else {
            return config.getDefaultClientDsaPrimeP();
        }
    }

    @Override
    public BigInteger getDsaClientPrimeQ() {
        if (tlsContext.getClientDsaPrimeQ() != null) {
            return tlsContext.getClientDsaPrimeQ();
        } else {
            return config.getDefaultClientDsaPrimeQ();
        }
    }

    @Override
    public BigInteger getDsaClientGenerator() {
        if (tlsContext.getClientDsaGenerator() != null) {
            return tlsContext.getClientDsaGenerator();
        } else {
            return config.getDefaultClientDsaGenerator();
        }
    }

    @Override
    public BigInteger getDsaServerPrivateKey() {
        if (tlsContext.getServerDsaPrivateKey() != null) {
            return tlsContext.getServerDsaPrivateKey();
        } else {
            return config.getDefaultServerDsaPrivateKey();
        }
    }

    @Override
    public BigInteger getDsaServerPublicKey() {
        if (tlsContext.getServerDsaPublicKey() != null) {
            return tlsContext.getServerDsaPublicKey();
        } else {
            return config.getDefaultServerDsaPublicKey();
        }
    }

    @Override
    public BigInteger getDsaServerPrimeP() {
        if (tlsContext.getServerDsaPrimeP() != null) {
            return tlsContext.getServerDsaPrimeP();
        } else {
            return config.getDefaultServerDsaPrimeP();
        }
    }

    @Override
    public BigInteger getDsaServerPrimeQ() {
        if (tlsContext.getServerDsaPrimeQ() != null) {
            return tlsContext.getServerDsaPrimeQ();
        } else {
            return config.getDefaultServerDsaPrimeQ();
        }
    }

    @Override
    public BigInteger getDsaServerGenerator() {
        if (tlsContext.getServerDsaGenerator() != null) {
            return tlsContext.getServerDsaGenerator();
        } else {
            return config.getDefaultServerDsaGenerator();
        }
    }

    @Override
    public byte[] getHandshakeSecret() {
        if (tlsContext.getHandshakeSecret() != null) {
            return copy(tlsContext.getHandshakeSecret());
        } else {
            return config.getDefaultHandshakeSecret();
        }
    }

    private byte[] copy(byte[] array) {
        return Arrays.copyOf(array, array.length);
    }

    @Override
    public String getClientPWDUsername() {
        if (tlsContext.getClientPWDUsername() != null) {
            return tlsContext.getClientPWDUsername();
        } else {
            return config.getDefaultClientPWDUsername();
        }
    }

    @Override
    public byte[] getServerPWDSalt() {
        if (tlsContext.getServerPWDSalt() != null) {
            return tlsContext.getServerPWDSalt();
        } else {
            return config.getDefaultServerPWDSalt();
        }
    }

    @Override
    public String getPWDPassword() {
        return config.getDefaultPWDPassword();
    }

    @Override
    public byte[] getEsniClientNonce() {
        if (tlsContext.getEsniClientNonce() != null) {
            return this.tlsContext.getEsniClientNonce();
        } else {
            return config.getDefaultEsniClientNonce();
        }
    }

    @Override
    public byte[] getEsniServerNonce() {
        if (tlsContext.getEsniServerNonce() != null) {
            return this.tlsContext.getEsniServerNonce();
        } else {
            return config.getDefaultEsniServerNonce();
        }
    }

    @Override
    public byte[] getEsniRecordBytes() {
        if (tlsContext.getEsniRecordBytes() != null) {
            return tlsContext.getEsniRecordBytes();
        } else {
            return config.getDefaultEsniRecordBytes();
        }
    }

    @Override
    public EsniDnsKeyRecordVersion getEsniRecordVersion() {
        if (tlsContext.getEsniRecordVersion() != null) {
            return tlsContext.getEsniRecordVersion();
        } else {
            return config.getDefaultEsniRecordVersion();
        }
    }

    @Override
    public byte[] getEsniRecordChecksum() {
        if (tlsContext.getEsniRecordChecksum() != null) {
            return tlsContext.getEsniRecordChecksum();
        } else {
            return config.getDefaultEsniRecordChecksum();
        }
    }

    @Override
    public List<KeyShareStoreEntry> getEsniServerKeyShareEntries() {
        if (tlsContext.getEsniServerKeyShareEntries() != null && tlsContext.getEsniServerKeyShareEntries().size() > 0) {
            return tlsContext.getEsniServerKeyShareEntries();
        } else {
            return config.getDefaultEsniServerKeyShareEntries();
        }
    }

    @Override
    public List<CipherSuite> getEsniServerCipherSuites() {

        if (tlsContext.getEsniServerCipherSuites() != null) {
            return tlsContext.getEsniServerCipherSuites();
        } else {
            return config.getDefaultEsniServerCipherSuites();
        }
    }

    @Override
    public Integer getEsniPaddedLength() {

        if (tlsContext.getEsniPaddedLength() != null) {
            return tlsContext.getEsniPaddedLength();
        } else {
            return config.getDefaultEsniPaddedLength();
        }
    }

    @Override
    public Long getEsniNotBefore() {
        if (tlsContext.getEsniKeysNotBefore() != null) {
            return this.tlsContext.getEsniKeysNotBefore();
        } else {
            return config.getDefaultEsniNotBefore();
        }
    }

    @Override
    public Long getEsniNotAfter() {
        if (tlsContext.getEsniNotAfter() != null) {
            return tlsContext.getEsniNotAfter();
        } else {
            return config.getDefaultEsniNotAfter();
        }
    }

    @Override
    public List<String> getProposedAlpnProtocols() {
        if (tlsContext.getProposedAlpnProtocols() != null) {
            return tlsContext.getProposedAlpnProtocols();
        } else {
            return config.getDefaultProposedAlpnProtocols();
        }
    }

    public Integer getMaxEarlyDataSize() {
        if (tlsContext.getMaxEarlyDataSize() != null) {
            return tlsContext.getMaxEarlyDataSize();
        } else {
            return config.getDefaultMaxEarlyDataSize();
        }
    }

    @Override
    public byte[] getLastClientHello() {
        if (tlsContext.getLastClientHello() != null) {
            return tlsContext.getLastClientHello();
        } else {
            return config.getDefaultLastClientHello();
        }
    }

    @Override
    public byte[] getExtensionCookie() {
        if (tlsContext.getExtensionCookie() != null) {
            return tlsContext.getExtensionCookie();
        } else {
            return config.getDefaultExtensionCookie();
        }
    }

    @Override
    public Integer getOutboundRecordSizeLimit() {
        if (tlsContext.getOutboundRecordSizeLimit() != null) {
            return tlsContext.getOutboundRecordSizeLimit();
        } else {
            return config.getDefaultMaxRecordData();
        }
    }

    @Override
    public Integer getInboundRecordSizeLimit() {
        if (config.getInboundRecordSizeLimit() != null) {
            return config.getInboundRecordSizeLimit();
        } else {
            return config.getDefaultMaxRecordData();
        }
    }

    @Override
    public Integer getOutboundMaxRecordDataSize() {
        if (tlsContext != null) {
            return tlsContext.getOutboundMaxRecordDataSize();
        } else {
            return config.getDefaultMaxRecordData();
        }
    }

    @Override
    public Integer getInboundMaxRecordDataSize() {
        if (tlsContext != null) {
            return tlsContext.getInboundMaxRecordDataSize();
        } else {
            return config.getDefaultMaxRecordData();
        }
    }

}
