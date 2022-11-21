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
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.EsniDnsKeyRecordVersion;
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.bouncycastle.util.Arrays;

public class DefaultChooser extends Chooser {

    DefaultChooser(TlsContext context, Config config) {
        super(context, config);
    }

    @Override
    public CertificateType getSelectedClientCertificateType() {
        if (context.getSelectedClientCertificateType() != null) {
            return context.getSelectedClientCertificateType();
        } else {
            return config.getDefaultSelectedClientCertificateType();
        }
    }

    @Override
    public CertificateType getSelectedServerCertificateType() {
        if (context.getSelectedServerCertificateType() != null) {
            return context.getSelectedServerCertificateType();
        } else {
            return config.getDefaultSelectedServerCertificateType();
        }
    }

    @Override
    public List<ECPointFormat> getClientSupportedPointFormats() {
        if (context.getClientPointFormatsList() != null) {
            return context.getClientPointFormatsList();
        } else {
            return config.getDefaultClientSupportedPointFormats();
        }
    }

    @Override
    public SignatureAndHashAlgorithm getSelectedSigHashAlgorithm() {
        if (context.getSelectedSignatureAndHashAlgorithm() != null) {
            return context.getSelectedSignatureAndHashAlgorithm();
        } else {
            return config.getDefaultSelectedSignatureAndHashAlgorithm();
        }
    }

    @Override
    public List<NamedGroup> getClientSupportedNamedGroups() {
        if (context.getClientNamedGroupsList() != null) {
            return context.getClientNamedGroupsList();
        } else {
            return config.getDefaultClientNamedGroups();
        }
    }

    @Override
    public List<NamedGroup> getServerSupportedNamedGroups() {
        if (context.getServerNamedGroupsList() != null) {
            return context.getServerNamedGroupsList();
        } else {
            return config.getDefaultServerNamedGroups();
        }
    }

    @Override
    public List<ECPointFormat> getServerSupportedPointFormats() {
        if (context.getServerPointFormatsList() != null) {
            return context.getServerPointFormatsList();
        } else {
            return config.getDefaultServerSupportedPointFormats();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
        if (context.getClientSupportedSignatureAndHashAlgorithms() != null) {
            return context.getClientSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultClientSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getClientSupportedCertificateSignAlgorithms() {
        if (context.getClientSupportedCertificateSignAlgorithms() != null) {
            return context.getClientSupportedCertificateSignAlgorithms();
        } else {
            return config.getDefaultClientSupportedCertificateSignAlgorithms();
        }
    }

    @Override
    public ProtocolVersion getLastRecordVersion() {
        if (context.getLastRecordVersion() != null) {
            return context.getLastRecordVersion();
        } else {
            return config.getDefaultLastRecordProtocolVersion();
        }
    }

    @Override
    public byte[] getDistinguishedNames() {
        if (context.getDistinguishedNames() != null) {
            return copy(context.getDistinguishedNames());
        } else {
            return config.getDistinguishedNames();
        }
    }

    @Override
    public List<ClientCertificateType> getClientCertificateTypes() {
        if (context.getClientCertificateTypes() != null) {
            return context.getClientCertificateTypes();
        } else {
            return config.getClientCertificateTypes();
        }
    }

    @Override
    public MaxFragmentLength getMaxFragmentLength() {
        if (context.getMaxFragmentLength() != null) {
            return context.getMaxFragmentLength();
        } else {
            return config.getDefaultMaxFragmentLength();
        }
    }

    @Override
    public HeartbeatMode getHeartbeatMode() {
        if (context.getHeartbeatMode() != null) {
            return context.getHeartbeatMode();
        } else {
            return config.getDefaultHeartbeatMode();
        }
    }

    @Override
    public boolean isUseExtendedMasterSecret() {
        return context.isUseExtendedMasterSecret();
    }

    @Override
    public List<CompressionMethod> getClientSupportedCompressions() {
        if (context.getClientSupportedCompressions() != null) {
            return context.getClientSupportedCompressions();
        } else {
            return config.getDefaultClientSupportedCompressionMethods();
        }
    }

    @Override
    public List<CipherSuite> getClientSupportedCipherSuites() {
        if (context.getClientSupportedCipherSuites() != null) {
            return context.getClientSupportedCipherSuites();
        } else {
            return config.getDefaultClientSupportedCipherSuites();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms() {
        if (context.getServerSupportedSignatureAndHashAlgorithms() != null) {
            return context.getServerSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultServerSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getServerSupportedCertificateSignAlgorithms() {
        if (context.getServerSupportedCertificateSignAlgorithms() != null) {
            return context.getServerSupportedCertificateSignAlgorithms();
        } else {
            return config.getDefaultServerSupportedCertificateSignAlgorithms();
        }
    }

    @Override
    public ProtocolVersion getSelectedProtocolVersion() {
        if (context.getSelectedProtocolVersion() != null) {
            return context.getSelectedProtocolVersion();
        } else {
            return config.getDefaultSelectedProtocolVersion();
        }
    }

    @Override
    public ProtocolVersion getHighestClientProtocolVersion() {
        if (context.getHighestClientProtocolVersion() != null) {
            return context.getHighestClientProtocolVersion();
        } else {
            return config.getDefaultHighestClientProtocolVersion();
        }
    }

    @Override
    public ConnectionEndType getTalkingConnectionEnd() {
        return context.getTalkingConnectionEndType();
    }

    @Override
    public byte[] getMasterSecret() {
        if (context.getMasterSecret() != null) {
            return copy(context.getMasterSecret());
        } else {
            return config.getDefaultMasterSecret();
        }
    }

    @Override
    public CipherSuite getSelectedCipherSuite() {
        if (context.getSelectedCipherSuite() != null) {
            return context.getSelectedCipherSuite();
        } else {
            return config.getDefaultSelectedCipherSuite();
        }
    }

    @Override
    public SSL2CipherSuite getSSL2CipherSuite() {
        if (context.getSSL2CipherSuite() != null) {
            return context.getSSL2CipherSuite();
        } else {
            return config.getDefaultSSL2CipherSuite();
        }
    }

    @Override
    public byte[] getPreMasterSecret() {
        if (context.getPreMasterSecret() != null) {
            return copy(context.getPreMasterSecret());
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
        if (context.getClientRandom() != null) {
            return copy(context.getClientRandom());
        } else {
            return config.getDefaultClientRandom();
        }
    }

    @Override
    public byte[] getClientExtendedRandom() {
        if (context.getClientExtendedRandom() != null) {
            return copy(context.getClientExtendedRandom());
        } else {
            return config.getDefaultClientExtendedRandom();
        }
    }

    @Override
    public byte[] getServerExtendedRandom() {
        if (context.getServerExtendedRandom() != null) {
            return copy(context.getServerExtendedRandom());
        } else {
            return config.getDefaultServerExtendedRandom();
        }
    }

    /**
     * Additional Check for Extended Random. If extended Random was negotiated, we add the additional bytes to the
     * Server Random
     */
    @Override
    public byte[] getServerRandom() {
        if (context.getServerRandom() != null) {
            return copy(context.getServerRandom());
        } else {
            return config.getDefaultServerRandom();
        }
    }

    @Override
    public CompressionMethod getSelectedCompressionMethod() {
        if (context.getSelectedCompressionMethod() != null) {
            return context.getSelectedCompressionMethod();
        } else {
            return config.getDefaultSelectedCompressionMethod();
        }
    }

    @Override
    public byte[] getClientSessionId() {
        if (context.getClientSessionId() != null) {
            return copy(context.getClientSessionId());
        } else {
            return config.getDefaultClientSessionId();
        }
    }

    @Override
    public byte[] getServerSessionId() {
        if (context.getServerSessionId() != null) {
            return copy(context.getServerSessionId());
        } else {
            return config.getDefaultServerSessionId();
        }
    }

    @Override
    public byte[] getDtlsCookie() {
        if (context.getDtlsCookie() != null) {
            return copy(context.getDtlsCookie());
        } else {
            return config.getDtlsDefaultCookie();
        }
    }

    @Override
    public TransportHandler getTransportHandler() {
        return context.getTransportHandler();
    }

    @Override
    public PRFAlgorithm getPRFAlgorithm() {
        if (context.getPrfAlgorithm() != null) {
            return context.getPrfAlgorithm();
        } else {
            return config.getDefaultPRFAlgorithm();
        }
    }

    @Override
    public byte[] getLatestSessionTicket() {
        if (context.getLatestSessionTicket() != null) {
            return context.getLatestSessionTicket();
        } else {
            return config.getTlsSessionTicket();
        }
    }

    @Override
    public byte[] getSignedCertificateTimestamp() {
        if (context.getSignedCertificateTimestamp() != null) {
            return copy(context.getSignedCertificateTimestamp());
        } else {
            return config.getDefaultSignedCertificateTimestamp();
        }
    }

    @Override
    public TokenBindingVersion getTokenBindingVersion() {
        if (context.getTokenBindingVersion() != null) {
            return context.getTokenBindingVersion();
        } else {
            return config.getDefaultTokenBindingVersion();
        }
    }

    @Override
    public List<TokenBindingKeyParameters> getTokenBindingKeyParameters() {
        if (context.getTokenBindingKeyParameters() != null) {
            return context.getTokenBindingKeyParameters();
        } else {
            return config.getDefaultTokenBindingKeyParameters();
        }
    }

    @Override
    public BigInteger getServerDhModulus() {
        if (context.getServerDhModulus() != null) {
            return context.getServerDhModulus();
        } else {
            return config.getDefaultServerDhModulus();
        }
    }

    @Override
    public BigInteger getServerDhGenerator() {
        if (context.getServerDhGenerator() != null) {
            return context.getServerDhGenerator();
        } else {
            return config.getDefaultServerDhGenerator();
        }
    }

    @Override
    public BigInteger getClientDhModulus() {
        if (context.getClientDhModulus() != null) {
            return context.getClientDhModulus();
        } else {
            return config.getDefaultClientDhModulus();
        }
    }

    @Override
    public BigInteger getClientDhGenerator() {
        if (context.getClientDhGenerator() != null) {
            return context.getClientDhGenerator();
        } else {
            return config.getDefaultClientDhGenerator();
        }
    }

    @Override
    public BigInteger getServerDhPrivateKey() {
        if (context.getServerDhPrivateKey() != null) {
            return context.getServerDhPrivateKey();
        } else {
            return config.getDefaultServerDhPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPModulus() {
        if (context.getSRPModulus() != null) {
            return context.getSRPModulus();
        } else {
            return config.getDefaultSRPModulus();
        }
    }

    @Override
    public byte[] getPSKIdentity() {
        if (context.getPSKIdentity() != null) {
            return copy(context.getPSKIdentity());
        } else {
            return config.getDefaultPSKIdentity();
        }
    }

    @Override
    public byte[] getPSKIdentityHint() {
        if (context.getPSKIdentityHint() != null) {
            return copy(context.getPSKIdentityHint());
        } else {
            return config.getDefaultPSKIdentityHint();
        }
    }

    @Override
    public BigInteger getPSKModulus() {
        if (context.getPSKModulus() != null) {
            return context.getPSKModulus();
        } else {
            return config.getDefaultPSKModulus();
        }
    }

    @Override
    public BigInteger getPSKServerPrivateKey() {
        if (context.getServerPSKPrivateKey() != null) {
            return context.getServerPSKPrivateKey();
        } else {
            return config.getDefaultPSKServerPrivateKey();
        }
    }

    @Override
    public BigInteger getPSKServerPublicKey() {
        if (context.getServerPSKPublicKey() != null) {
            return context.getServerPSKPublicKey();
        } else {
            return config.getDefaultPSKServerPublicKey();
        }
    }

    @Override
    public BigInteger getPSKGenerator() {
        if (context.getPSKGenerator() != null) {
            return context.getPSKGenerator();
        } else {
            return config.getDefaultPSKGenerator();
        }
    }

    @Override
    public BigInteger getSRPGenerator() {
        if (context.getSRPGenerator() != null) {
            return context.getSRPGenerator();
        } else {
            return config.getDefaultSRPGenerator();
        }
    }

    @Override
    public BigInteger getSRPServerPrivateKey() {
        if (context.getServerSRPPrivateKey() != null) {
            return context.getServerSRPPrivateKey();
        } else {
            return config.getDefaultSRPServerPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPServerPublicKey() {
        if (context.getServerSRPPublicKey() != null) {
            return context.getServerSRPPublicKey();
        } else {
            return config.getDefaultSRPServerPublicKey();
        }
    }

    @Override
    public BigInteger getSRPClientPrivateKey() {
        if (context.getClientSRPPrivateKey() != null) {
            return context.getClientSRPPrivateKey();
        } else {
            return config.getDefaultSRPClientPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPClientPublicKey() {
        if (context.getClientSRPPublicKey() != null) {
            return context.getClientSRPPublicKey();
        } else {
            return config.getDefaultSRPClientPublicKey();
        }
    }

    @Override
    public byte[] getSRPPassword() {
        if (context.getSRPPassword() != null) {
            return copy(context.getSRPPassword());
        } else {
            return config.getDefaultSRPPassword();
        }
    }

    @Override
    public byte[] getSRPIdentity() {
        if (context.getSRPIdentity() != null) {
            return copy(context.getSRPIdentity());
        } else {
            return config.getDefaultSRPIdentity();
        }
    }

    @Override
    public byte[] getSRPServerSalt() {
        if (context.getSRPServerSalt() != null) {
            return copy(context.getSRPServerSalt());
        } else {
            return config.getDefaultSRPServerSalt();
        }
    }

    @Override
    public BigInteger getClientDhPrivateKey() {
        if (context.getClientDhPrivateKey() != null) {
            return context.getClientDhPrivateKey();
        } else {
            return config.getDefaultClientDhPrivateKey();
        }
    }

    @Override
    public BigInteger getServerDhPublicKey() {
        if (context.getServerDhPublicKey() != null) {
            return context.getServerDhPublicKey();
        } else {
            return config.getDefaultServerDhPublicKey();
        }
    }

    @Override
    public BigInteger getClientDhPublicKey() {
        if (context.getClientDhPublicKey() != null) {
            return context.getClientDhPublicKey();
        } else {
            return config.getDefaultClientDhPublicKey();
        }
    }

    @Override
    public BigInteger getServerEcPrivateKey() {
        if (context.getServerEcPrivateKey() != null) {
            return context.getServerEcPrivateKey();
        } else {
            return config.getDefaultServerEcPrivateKey();
        }
    }

    @Override
    public GOSTCurve getSelectedGostCurve() {
        if (context.getSelectedGostCurve() != null) {
            return context.getSelectedGostCurve();
        } else {
            return config.getDefaultSelectedGostCurve();
        }
    }

    @Override
    public BigInteger getClientEcPrivateKey() {
        if (context.getClientEcPrivateKey() != null) {
            return context.getClientEcPrivateKey();
        } else {
            return config.getDefaultClientEcPrivateKey();
        }
    }

    @Override
    public NamedGroup getSelectedNamedGroup() {
        if (context.getSelectedGroup() != null) {
            return context.getSelectedGroup();
        } else {
            return config.getDefaultSelectedNamedGroup();
        }
    }

    @Override
    public NamedGroup getEcCertificateCurve() {
        if (context.getEcCertificateCurve() != null) {
            return context.getEcCertificateCurve();
        } else {
            return config.getDefaultEcCertificateCurve();
        }
    }

    @Override
    public Point getClientEcPublicKey() {
        if (context.getClientEcPublicKey() != null) {
            return context.getClientEcPublicKey();
        } else {
            return config.getDefaultClientEcPublicKey();
        }
    }

    @Override
    public Point getServerEcPublicKey() {
        if (context.getServerEcPublicKey() != null) {
            return context.getServerEcPublicKey();
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
        if (context.getServerRSAModulus() != null) {
            return context.getServerRSAModulus();
        } else {
            return config.getDefaultServerRSAModulus();
        }
    }

    @Override
    public BigInteger getClientRsaModulus() {
        if (context.getClientRsaModulus() != null) {
            return context.getClientRsaModulus();
        } else {
            return config.getDefaultClientRSAModulus();
        }
    }

    @Override
    public BigInteger getServerRSAPublicKey() {
        if (context.getServerRSAPublicKey() != null) {
            return context.getServerRSAPublicKey();
        } else {
            return config.getDefaultServerRSAPublicKey();
        }
    }

    @Override
    public BigInteger getClientRSAPublicKey() {
        if (context.getClientRSAPublicKey() != null) {
            return context.getClientRSAPublicKey();
        } else {
            return config.getDefaultClientRSAPublicKey();
        }
    }

    @Override
    public byte[] getCertificateRequestContext() {
        if (context.getCertificateRequestContext() != null) {
            return copy(context.getCertificateRequestContext());
        } else {
            return config.getDefaultCertificateRequestContext();
        }
    }

    @Override
    public byte[] getServerHandshakeTrafficSecret() {
        if (context.getServerHandshakeTrafficSecret() != null) {
            return copy(context.getServerHandshakeTrafficSecret());
        } else {
            return config.getDefaultServerHandshakeTrafficSecret();
        }
    }

    @Override
    public byte[] getClientHandshakeTrafficSecret() {
        if (context.getClientHandshakeTrafficSecret() != null) {
            return copy(context.getClientHandshakeTrafficSecret());
        } else {
            return config.getDefaultClientHandshakeTrafficSecret();
        }
    }

    @Override
    public byte[] getClientApplicationTrafficSecret() {
        if (context.getClientApplicationTrafficSecret() != null) {
            return copy(context.getClientApplicationTrafficSecret());
        } else {
            return config.getDefaultClientApplicationTrafficSecret();
        }

    }

    @Override
    public byte[] getServerApplicationTrafficSecret() {
        if (context.getServerApplicationTrafficSecret() != null) {
            return copy(context.getServerApplicationTrafficSecret());
        } else {
            return config.getDefaultServerApplicationTrafficSecret();
        }
    }

    @Override
    public RecordLayerType getRecordLayerType() {
        if (context.getRecordLayerType() != null) {
            return context.getRecordLayerType();
        } else {
            return config.getRecordLayerType();
        }
    }

    @Override
    public BigInteger getClientRSAPrivateKey() {
        if (context.getClientRSAPrivateKey() != null) {
            return context.getClientRSAPrivateKey();
        } else {
            return config.getDefaultClientRSAPrivateKey();
        }
    }

    @Override
    public BigInteger getServerRSAPrivateKey() {
        if (context.getServerRSAPrivateKey() != null) {
            return context.getServerRSAPrivateKey();
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
        if (context.getHighestProtocolVersion() != null) {
            return context.getHighestProtocolVersion();
        } else {
            return config.getHighestProtocolVersion();
        }
    }

    @Override
    public boolean isClientAuthentication() {
        if (context.isClientAuthentication() != null) {
            return context.isClientAuthentication();
        } else {
            return config.isClientAuthentication();
        }
    }

    @Override
    public byte[] getLastHandledApplicationMessageData() {
        if (context.getLastHandledApplicationMessageData() != null) {
            return copy(context.getLastHandledApplicationMessageData());
        } else {
            return config.getDefaultApplicationMessageData().getBytes(StandardCharsets.ISO_8859_1);
        }
    }

    @Override
    public byte[] getPsk() {
        if (context.getPsk() != null) {
            return copy(context.getPsk());
        } else {
            return config.getPsk();
        }
    }

    @Override
    public String getHttpsCookieValue() {
        String cookieVal = context.getHttpsCookieValue();
        if (cookieVal != null && !cookieVal.isEmpty()) {
            return cookieVal;
        } else {
            return config.getDefaultHttpsCookieValue();
        }
    }

    @Override
    public String getHttpsCookieName() {
        String cookieName = context.getHttpsCookieName();
        if (cookieName != null && !cookieName.isEmpty()) {
            return cookieName;
        } else {
            return config.getDefaultHttpsCookieName();
        }
    }

    @Override
    public List<PskSet> getPskSets() {
        if (context.getPskSets() != null) {
            return context.getPskSets();
        } else {
            return config.getDefaultPskSets();
        }
    }

    @Override
    public CipherSuite getEarlyDataCipherSuite() {
        if (context.getEarlyDataCipherSuite() != null) {
            return context.getEarlyDataCipherSuite();
        } else {
            return config.getEarlyDataCipherSuite();
        }
    }

    @Override
    public byte[] getClientEarlyTrafficSecret() {
        if (context.getClientEarlyTrafficSecret() != null) {
            return copy(context.getClientEarlyTrafficSecret());
        } else {
            return config.getClientEarlyTrafficSecret();
        }
    }

    @Override
    public byte[] getEarlySecret() {
        if (context.getEarlySecret() != null) {
            return copy(context.getEarlySecret());
        } else {
            return config.getEarlySecret();
        }
    }

    @Override
    public byte[] getEarlyDataPsk() {
        if (context.getEarlyDataPsk() != null) {
            return copy(context.getEarlyDataPsk());
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
        if (context.getClientKeyShareStoreEntryList() != null) {
            return context.getClientKeyShareStoreEntryList();
        } else {
            return config.getDefaultClientKeyStoreEntries();
        }
    }

    @Override
    public KeyShareStoreEntry getServerKeyShare() {
        if (context.getServerKeyShareStoreEntry() != null) {
            return context.getServerKeyShareStoreEntry();
        } else {
            return config.getDefaultServerKeyShareEntry();
        }
    }

    @Override
    public BigInteger getDsaClientPrivateKey() {
        if (context.getClientDsaPrivateKey() != null) {
            return context.getClientDsaPrivateKey();
        } else {
            return config.getDefaultClientDsaPrivateKey();
        }
    }

    @Override
    public BigInteger getDsaClientPublicKey() {
        if (context.getClientDsaPublicKey() != null) {
            return context.getClientDsaPublicKey();
        } else {
            return config.getDefaultClientDsaPublicKey();
        }
    }

    @Override
    public BigInteger getDsaClientPrimeP() {
        if (context.getClientDsaPrimeP() != null) {
            return context.getClientDsaPrimeP();
        } else {
            return config.getDefaultClientDsaPrimeP();
        }
    }

    @Override
    public BigInteger getDsaClientPrimeQ() {
        if (context.getClientDsaPrimeQ() != null) {
            return context.getClientDsaPrimeQ();
        } else {
            return config.getDefaultClientDsaPrimeQ();
        }
    }

    @Override
    public BigInteger getDsaClientGenerator() {
        if (context.getClientDsaGenerator() != null) {
            return context.getClientDsaGenerator();
        } else {
            return config.getDefaultClientDsaGenerator();
        }
    }

    @Override
    public BigInteger getDsaServerPrivateKey() {
        if (context.getServerDsaPrivateKey() != null) {
            return context.getServerDsaPrivateKey();
        } else {
            return config.getDefaultServerDsaPrivateKey();
        }
    }

    @Override
    public BigInteger getDsaServerPublicKey() {
        if (context.getServerDsaPublicKey() != null) {
            return context.getServerDsaPublicKey();
        } else {
            return config.getDefaultServerDsaPublicKey();
        }
    }

    @Override
    public BigInteger getDsaServerPrimeP() {
        if (context.getServerDsaPrimeP() != null) {
            return context.getServerDsaPrimeP();
        } else {
            return config.getDefaultServerDsaPrimeP();
        }
    }

    @Override
    public BigInteger getDsaServerPrimeQ() {
        if (context.getServerDsaPrimeQ() != null) {
            return context.getServerDsaPrimeQ();
        } else {
            return config.getDefaultServerDsaPrimeQ();
        }
    }

    @Override
    public BigInteger getDsaServerGenerator() {
        if (context.getServerDsaGenerator() != null) {
            return context.getServerDsaGenerator();
        } else {
            return config.getDefaultServerDsaGenerator();
        }
    }

    @Override
    public byte[] getHandshakeSecret() {
        if (context.getHandshakeSecret() != null) {
            return copy(context.getHandshakeSecret());
        } else {
            return config.getDefaultHandshakeSecret();
        }
    }

    private byte[] copy(byte[] array) {
        return Arrays.copyOf(array, array.length);
    }

    @Override
    public String getClientPWDUsername() {
        if (context.getClientPWDUsername() != null) {
            return context.getClientPWDUsername();
        } else {
            return config.getDefaultClientPWDUsername();
        }
    }

    @Override
    public byte[] getServerPWDSalt() {
        if (context.getServerPWDSalt() != null) {
            return context.getServerPWDSalt();
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
        if (context.getEsniClientNonce() != null) {
            return this.context.getEsniClientNonce();
        } else {
            return config.getDefaultEsniClientNonce();
        }
    }

    @Override
    public byte[] getEsniServerNonce() {
        if (context.getEsniServerNonce() != null) {
            return this.context.getEsniServerNonce();
        } else {
            return config.getDefaultEsniServerNonce();
        }
    }

    @Override
    public byte[] getEsniRecordBytes() {
        if (context.getEsniRecordBytes() != null) {
            return context.getEsniRecordBytes();
        } else {
            return config.getDefaultEsniRecordBytes();
        }
    }

    @Override
    public EsniDnsKeyRecordVersion getEsniRecordVersion() {
        if (context.getEsniRecordVersion() != null) {
            return context.getEsniRecordVersion();
        } else {
            return config.getDefaultEsniRecordVersion();
        }
    }

    @Override
    public byte[] getEsniRecordChecksum() {
        if (context.getEsniRecordChecksum() != null) {
            return context.getEsniRecordChecksum();
        } else {
            return config.getDefaultEsniRecordChecksum();
        }
    }

    @Override
    public List<KeyShareStoreEntry> getEsniServerKeyShareEntries() {
        if (context.getEsniServerKeyShareEntries() != null && context.getEsniServerKeyShareEntries().size() > 0) {
            return context.getEsniServerKeyShareEntries();
        } else {
            return config.getDefaultEsniServerKeyShareEntries();
        }
    }

    @Override
    public List<CipherSuite> getEsniServerCipherSuites() {

        if (context.getEsniServerCipherSuites() != null) {
            return context.getEsniServerCipherSuites();
        } else {
            return config.getDefaultEsniServerCipherSuites();
        }
    }

    @Override
    public Integer getEsniPaddedLength() {

        if (context.getEsniPaddedLength() != null) {
            return context.getEsniPaddedLength();
        } else {
            return config.getDefaultEsniPaddedLength();
        }
    }

    @Override
    public Long getEsniNotBefore() {
        if (context.getEsniKeysNotBefore() != null) {
            return this.context.getEsniKeysNotBefore();
        } else {
            return config.getDefaultEsniNotBefore();
        }
    }

    @Override
    public Long getEsniNotAfter() {
        if (context.getEsniNotAfter() != null) {
            return context.getEsniNotAfter();
        } else {
            return config.getDefaultEsniNotAfter();
        }
    }

    @Override
    public List<String> getProposedAlpnProtocols() {
        if (context.getProposedAlpnProtocols() != null) {
            return context.getProposedAlpnProtocols();
        } else {
            return config.getDefaultProposedAlpnProtocols();
        }
    }

    public Integer getMaxEarlyDataSize() {
        if (context.getMaxEarlyDataSize() != null) {
            return context.getMaxEarlyDataSize();
        } else {
            return config.getDefaultMaxEarlyDataSize();
        }
    }

    @Override
    public byte[] getLastClientHello() {
        if (context.getLastClientHello() != null) {
            return context.getLastClientHello();
        } else {
            return config.getDefaultLastClientHello();
        }
    }

    @Override
    public byte[] getExtensionCookie() {
        if (context.getExtensionCookie() != null) {
            return context.getExtensionCookie();
        } else {
            return config.getDefaultExtensionCookie();
        }
    }

    @Override
    public Integer getOutboundRecordSizeLimit() {
        if (context.getOutboundRecordSizeLimit() != null) {
            return context.getOutboundRecordSizeLimit();
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
        if (context != null) {
            return context.getOutboundMaxRecordDataSize();
        } else {
            return config.getDefaultMaxRecordData();
        }
    }

    @Override
    public Integer getInboundMaxRecordDataSize() {
        if (context != null) {
            return context.getInboundMaxRecordDataSize();
        } else {
            return config.getDefaultMaxRecordData();
        }
    }
}
