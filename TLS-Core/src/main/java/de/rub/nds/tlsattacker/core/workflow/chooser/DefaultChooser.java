/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
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
    public List<SNIEntry> getClientSNIEntryList() {
        if (context.getClientSNIEntryList() != null) {
            return context.getClientSNIEntryList();
        } else {
            return config.getDefaultClientSNIEntryList();
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
    public List<CipherSuite> getClientSupportedCiphersuites() {
        if (context.getClientSupportedCiphersuites() != null) {
            return context.getClientSupportedCiphersuites();
        } else {
            return config.getDefaultClientSupportedCiphersuites();
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
    public byte[] getPreMasterSecret() {
        if (context.getPreMasterSecret() != null) {
            return copy(context.getPreMasterSecret());
        } else {
            return config.getDefaultPreMasterSecret();
        }
    }

    @Override
    public byte[] getClientRandom() {
        if (context.getClientRandom() != null) {
            return copy(context.getClientRandom());
        } else {
            return config.getDefaultClientRandom();
        }
    }

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
    public byte[] getSessionTicketTLS() {
        if (context.getSessionTicketTLS() != null) {
            return copy(context.getSessionTicketTLS());
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
    public BigInteger getDhServerPrivateKey() {
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
    public BigInteger getDhClientPrivateKey() {
        if (context.getClientDhPrivateKey() != null) {
            return context.getClientDhPrivateKey();
        } else {
            return config.getDefaultClientDhPrivateKey();
        }
    }

    @Override
    public BigInteger getDhServerPublicKey() {
        if (context.getServerDhPublicKey() != null) {
            return context.getServerDhPublicKey();
        } else {
            return config.getDefaultServerDhPublicKey();
        }
    }

    @Override
    public BigInteger getDhClientPublicKey() {
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
        if (context.getSelectedGroup() != null) {
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
        if (context.getServerRsaModulus() != null) {
            return context.getServerRsaModulus();
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
            return config.getDefaultApplicationMessageData().getBytes();
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
            return config.getDefaultClientKeyShareEntries();
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
    public BigInteger getDsaPrimeP() {
        if (context.getServerDsaPrimeP() != null) {
            return context.getServerDsaPrimeP();
        } else {
            return config.getDefaultServerDsaPrimeP();
        }
    }

    @Override
    public BigInteger getDsaPrimeQ() {
        if (context.getServerDsaPrimeQ() != null) {
            return context.getServerDsaPrimeQ();
        } else {
            return config.getDefaultServerDsaPrimeQ();
        }
    }

    @Override
    public BigInteger getDsaGenerator() {
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
        return context.getServerPWDSalt();
    }

    @Override
    public String getPWDPassword() {
        return config.getDefaultPWDPassword();
    }
}
