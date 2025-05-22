/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.protocol.crypto.ec.Point;
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
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SrtpProtectionProfile;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareEntryPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.bouncycastle.util.Arrays;

public class DefaultChooser extends Chooser {

    DefaultChooser(Context context, Config config) {
        super(context, config);
    }

    @Override
    public CertificateType getSelectedClientCertificateType() {
        if (context.getTlsContext().getSelectedClientCertificateType() != null) {
            return context.getTlsContext().getSelectedClientCertificateType();
        } else {
            return config.getDefaultSelectedClientCertificateType();
        }
    }

    @Override
    public CertificateType getSelectedServerCertificateType() {
        if (context.getTlsContext().getSelectedServerCertificateType() != null) {
            return context.getTlsContext().getSelectedServerCertificateType();
        } else {
            return config.getDefaultSelectedServerCertificateType();
        }
    }

    @Override
    public List<ECPointFormat> getClientSupportedPointFormats() {
        if (context.getTlsContext().getClientPointFormatsList() != null) {
            return context.getTlsContext().getClientPointFormatsList();
        } else {
            return config.getDefaultClientSupportedPointFormats();
        }
    }

    @Override
    public SignatureAndHashAlgorithm getSelectedSigHashAlgorithm() {
        if (context.getTlsContext().getSelectedSignatureAndHashAlgorithm() != null) {
            return context.getTlsContext().getSelectedSignatureAndHashAlgorithm();
        } else {
            return config.getDefaultSelectedSignatureAndHashAlgorithm();
        }
    }

    @Override
    public List<NamedGroup> getClientSupportedNamedGroups() {
        if (context.getTlsContext().getClientNamedGroupsList() != null) {
            return context.getTlsContext().getClientNamedGroupsList();
        } else {
            return config.getDefaultClientNamedGroups();
        }
    }

    @Override
    public List<NamedGroup> getServerSupportedNamedGroups() {
        if (context.getTlsContext().getServerNamedGroupsList() != null) {
            return context.getTlsContext().getServerNamedGroupsList();
        } else {
            return config.getDefaultServerNamedGroups();
        }
    }

    @Override
    public List<ECPointFormat> getServerSupportedPointFormats() {
        if (context.getTlsContext().getServerPointFormatsList() != null) {
            return context.getTlsContext().getServerPointFormatsList();
        } else {
            return config.getDefaultServerSupportedPointFormats();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms() {
        if (context.getTlsContext().getClientSupportedSignatureAndHashAlgorithms() != null) {
            return context.getTlsContext().getClientSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultClientSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getClientSupportedCertificateSignAlgorithms() {
        if (context.getTlsContext().getClientSupportedCertificateSignAlgorithms() != null) {
            return context.getTlsContext().getClientSupportedCertificateSignAlgorithms();
        } else {
            return config.getDefaultClientSupportedCertificateSignAlgorithms();
        }
    }

    @Override
    public ProtocolVersion getLastRecordVersion() {
        if (context.getTlsContext().getLastRecordVersion() != null) {
            return context.getTlsContext().getLastRecordVersion();
        } else {
            return config.getDefaultLastRecordProtocolVersion();
        }
    }

    @Override
    public byte[] getDistinguishedNames() {
        if (context.getTlsContext().getDistinguishedNames() != null) {
            return copy(context.getTlsContext().getDistinguishedNames());
        } else {
            return config.getDistinguishedNames();
        }
    }

    @Override
    public List<ClientCertificateType> getClientCertificateTypes() {
        if (context.getTlsContext().getClientCertificateTypes() != null) {
            return context.getTlsContext().getClientCertificateTypes();
        } else {
            return config.getClientCertificateTypes();
        }
    }

    @Override
    public HeartbeatMode getHeartbeatMode() {
        if (context.getTlsContext().getHeartbeatMode() != null) {
            return context.getTlsContext().getHeartbeatMode();
        } else {
            return config.getDefaultHeartbeatMode();
        }
    }

    @Override
    public boolean isUseExtendedMasterSecret() {
        return context.getTlsContext().isUseExtendedMasterSecret();
    }

    @Override
    public List<CompressionMethod> getClientSupportedCompressions() {
        if (context.getTlsContext().getClientSupportedCompressions() != null) {
            return context.getTlsContext().getClientSupportedCompressions();
        } else {
            return config.getDefaultClientSupportedCompressionMethods();
        }
    }

    @Override
    public List<CipherSuite> getClientSupportedCipherSuites() {
        if (context.getTlsContext().getClientSupportedCipherSuites() != null) {
            return context.getTlsContext().getClientSupportedCipherSuites();
        } else {
            return config.getDefaultClientSupportedCipherSuites();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms() {
        if (context.getTlsContext().getServerSupportedSignatureAndHashAlgorithms() != null) {
            return context.getTlsContext().getServerSupportedSignatureAndHashAlgorithms();
        } else {
            return config.getDefaultServerSupportedSignatureAndHashAlgorithms();
        }
    }

    @Override
    public List<SignatureAndHashAlgorithm> getServerSupportedCertificateSignAlgorithms() {
        if (context.getTlsContext().getServerSupportedCertificateSignAlgorithms() != null) {
            return context.getTlsContext().getServerSupportedCertificateSignAlgorithms();
        } else {
            return config.getDefaultServerSupportedCertificateSignAlgorithms();
        }
    }

    @Override
    public ProtocolVersion getSelectedProtocolVersion() {
        if (context.getTlsContext().getSelectedProtocolVersion() != null) {
            return context.getTlsContext().getSelectedProtocolVersion();
        } else {
            return config.getDefaultSelectedProtocolVersion();
        }
    }

    @Override
    public ProtocolVersion getHighestClientProtocolVersion() {
        if (context.getTlsContext().getHighestClientProtocolVersion() != null) {
            return context.getTlsContext().getHighestClientProtocolVersion();
        } else {
            return config.getDefaultHighestClientProtocolVersion();
        }
    }

    @Override
    public ConnectionEndType getTalkingConnectionEnd() {
        return context.getTlsContext().getTalkingConnectionEndType();
    }

    @Override
    public byte[] getMasterSecret() {
        if (context.getTlsContext().getMasterSecret() != null) {
            return copy(context.getTlsContext().getMasterSecret());
        } else {
            return config.getDefaultMasterSecret();
        }
    }

    @Override
    public CipherSuite getSelectedCipherSuite() {
        if (context.getTlsContext().getSelectedCipherSuite() != null) {
            return context.getTlsContext().getSelectedCipherSuite();
        } else {
            return config.getDefaultSelectedCipherSuite();
        }
    }

    @Override
    public SSL2CipherSuite getSSL2CipherSuite() {
        if (context.getTlsContext().getSSL2CipherSuite() != null) {
            return context.getTlsContext().getSSL2CipherSuite();
        } else {
            return config.getDefaultSSL2CipherSuite();
        }
    }

    @Override
    public byte[] getPreMasterSecret() {
        if (context.getTlsContext().getPreMasterSecret() != null) {
            return copy(context.getTlsContext().getPreMasterSecret());
        } else {
            return config.getDefaultPreMasterSecret();
        }
    }

    @Override
    public byte[] getClientRandom() {
        if (context.getTlsContext().getClientRandom() != null) {
            return copy(context.getTlsContext().getClientRandom());
        } else {
            return config.getDefaultClientRandom();
        }
    }

    @Override
    public ClientHelloMessage getInnerClientHello() {
        if (context.getTlsContext().getInnerClientHello() != null) {
            return context.getTlsContext().getInnerClientHello();
        } else {
            return new ClientHelloMessage();
        }
    }

    @Override
    public byte[] getClientExtendedRandom() {
        if (context.getTlsContext().getClientExtendedRandom() != null) {
            return copy(context.getTlsContext().getClientExtendedRandom());
        } else {
            return config.getDefaultClientExtendedRandom();
        }
    }

    @Override
    public byte[] getServerExtendedRandom() {
        if (context.getTlsContext().getServerExtendedRandom() != null) {
            return copy(context.getTlsContext().getServerExtendedRandom());
        } else {
            return config.getDefaultServerExtendedRandom();
        }
    }

    @Override
    public byte[] getServerRandom() {
        if (context.getTlsContext().getServerRandom() != null) {
            return copy(context.getTlsContext().getServerRandom());
        } else {
            return config.getDefaultServerRandom();
        }
    }

    @Override
    public CompressionMethod getSelectedCompressionMethod() {
        if (context.getTlsContext().getSelectedCompressionMethod() != null) {
            return context.getTlsContext().getSelectedCompressionMethod();
        } else {
            return config.getDefaultSelectedCompressionMethod();
        }
    }

    @Override
    public byte[] getClientSessionId() {
        if (context.getTlsContext().getClientSessionId() != null) {
            return copy(context.getTlsContext().getClientSessionId());
        } else {
            return config.getDefaultClientSessionId();
        }
    }

    @Override
    public byte[] getServerSessionId() {
        if (context.getTlsContext().getServerSessionId() != null) {
            return copy(context.getTlsContext().getServerSessionId());
        } else {
            return config.getDefaultServerSessionId();
        }
    }

    @Override
    public byte[] getDtlsCookie() {
        if (context.getTlsContext().getDtlsCookie() != null) {
            return copy(context.getTlsContext().getDtlsCookie());
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
        if (context.getTlsContext().getPrfAlgorithm() != null) {
            return context.getTlsContext().getPrfAlgorithm();
        } else {
            return config.getDefaultPRFAlgorithm();
        }
    }

    @Override
    public byte[] getLatestSessionTicket() {
        if (context.getTlsContext().getLatestSessionTicket() != null) {
            return context.getTlsContext().getLatestSessionTicket();
        } else {
            return config.getTlsSessionTicket();
        }
    }

    @Override
    public byte[] getSignedCertificateTimestamp() {
        if (context.getTlsContext().getSignedCertificateTimestamp() != null) {
            return copy(context.getTlsContext().getSignedCertificateTimestamp());
        } else {
            return config.getDefaultSignedCertificateTimestamp();
        }
    }

    @Override
    public TokenBindingVersion getTokenBindingVersion() {
        if (context.getTlsContext().getTokenBindingVersion() != null) {
            return context.getTlsContext().getTokenBindingVersion();
        } else {
            return config.getDefaultTokenBindingVersion();
        }
    }

    @Override
    public List<TokenBindingKeyParameters> getTokenBindingKeyParameters() {
        if (context.getTlsContext().getTokenBindingKeyParameters() != null) {
            return context.getTlsContext().getTokenBindingKeyParameters();
        } else {
            return config.getDefaultTokenBindingKeyParameters();
        }
    }

    @Override
    public BigInteger getSRPModulus() {
        if (context.getTlsContext().getSRPModulus() != null) {
            return context.getTlsContext().getSRPModulus();
        } else {
            return config.getDefaultSRPModulus();
        }
    }

    @Override
    public byte[] getPSKIdentity() {
        if (context.getTlsContext().getPSKIdentity() != null) {
            return copy(context.getTlsContext().getPSKIdentity());
        } else {
            return config.getDefaultPSKIdentity();
        }
    }

    @Override
    public byte[] getPSKIdentityHint() {
        if (context.getTlsContext().getPSKIdentityHint() != null) {
            return copy(context.getTlsContext().getPSKIdentityHint());
        } else {
            return config.getDefaultPSKIdentityHint();
        }
    }

    @Override
    public BigInteger getSRPGenerator() {
        if (context.getTlsContext().getSRPGenerator() != null) {
            return context.getTlsContext().getSRPGenerator();
        } else {
            return config.getDefaultSRPGenerator();
        }
    }

    @Override
    public BigInteger getSRPServerPrivateKey() {
        if (context.getTlsContext().getServerSRPPrivateKey() != null) {
            return context.getTlsContext().getServerSRPPrivateKey();
        } else {
            return config.getDefaultSRPServerPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPServerPublicKey() {
        if (context.getTlsContext().getServerSRPPublicKey() != null) {
            return context.getTlsContext().getServerSRPPublicKey();
        } else {
            return config.getDefaultSRPServerPublicKey();
        }
    }

    @Override
    public BigInteger getSRPClientPrivateKey() {
        if (context.getTlsContext().getClientSRPPrivateKey() != null) {
            return context.getTlsContext().getClientSRPPrivateKey();
        } else {
            return config.getDefaultSRPClientPrivateKey();
        }
    }

    @Override
    public BigInteger getSRPClientPublicKey() {
        if (context.getTlsContext().getClientSRPPublicKey() != null) {
            return context.getTlsContext().getClientSRPPublicKey();
        } else {
            return config.getDefaultSRPClientPublicKey();
        }
    }

    @Override
    public byte[] getSRPPassword() {
        if (context.getTlsContext().getSRPPassword() != null) {
            return copy(context.getTlsContext().getSRPPassword());
        } else {
            return config.getDefaultSRPPassword();
        }
    }

    @Override
    public byte[] getSRPIdentity() {
        if (context.getTlsContext().getSRPIdentity() != null) {
            return copy(context.getTlsContext().getSRPIdentity());
        } else {
            return config.getDefaultSRPIdentity();
        }
    }

    @Override
    public byte[] getSRPServerSalt() {
        if (context.getTlsContext().getSRPServerSalt() != null) {
            return copy(context.getTlsContext().getSRPServerSalt());
        } else {
            return config.getDefaultSRPServerSalt();
        }
    }

    @Override
    public GOSTCurve getSelectedGostCurve() {
        if (context.getTlsContext().getSelectedGostCurve() != null) {
            return context.getTlsContext().getSelectedGostCurve();
        } else {
            return config.getDefaultSelectedGostCurve();
        }
    }

    @Override
    public NamedGroup getSelectedNamedGroup() {
        if (context.getTlsContext().getSelectedGroup() != null) {
            return context.getTlsContext().getSelectedGroup();
        } else {
            return config.getDefaultSelectedNamedGroup();
        }
    }

    @Override
    public EllipticCurveType getEcCurveType() {
        // We currently only support named curves TODO
        return EllipticCurveType.NAMED_CURVE;
    }

    @Override
    public byte[] getCertificateRequestContext() {
        if (context.getTlsContext().getCertificateRequestContext() != null) {
            return copy(context.getTlsContext().getCertificateRequestContext());
        } else {
            return config.getDefaultCertificateRequestContext();
        }
    }

    @Override
    public byte[] getServerHandshakeTrafficSecret() {
        if (context.getTlsContext().getServerHandshakeTrafficSecret() != null) {
            return copy(context.getTlsContext().getServerHandshakeTrafficSecret());
        } else {
            return config.getDefaultServerHandshakeTrafficSecret();
        }
    }

    @Override
    public byte[] getClientHandshakeTrafficSecret() {
        if (context.getTlsContext().getClientHandshakeTrafficSecret() != null) {
            return copy(context.getTlsContext().getClientHandshakeTrafficSecret());
        } else {
            return config.getDefaultClientHandshakeTrafficSecret();
        }
    }

    @Override
    public byte[] getClientApplicationTrafficSecret() {
        if (context.getTlsContext().getClientApplicationTrafficSecret() != null) {
            return copy(context.getTlsContext().getClientApplicationTrafficSecret());
        } else {
            return config.getDefaultClientApplicationTrafficSecret();
        }
    }

    @Override
    public byte[] getServerApplicationTrafficSecret() {
        if (context.getTlsContext().getServerApplicationTrafficSecret() != null) {
            return copy(context.getTlsContext().getServerApplicationTrafficSecret());
        } else {
            return config.getDefaultServerApplicationTrafficSecret();
        }
    }

    @Override
    public Connection getConnection() {
        return context.getConnection();
    }

    @Override
    public ConnectionEndType getMyConnectionPeer() {
        return getConnection().getLocalConnectionEndType() == ConnectionEndType.CLIENT
                ? ConnectionEndType.SERVER
                : ConnectionEndType.CLIENT;
    }

    @Override
    public ProtocolVersion getHighestProtocolVersion() {
        if (context.getTlsContext().getHighestProtocolVersion() != null) {
            return context.getTlsContext().getHighestProtocolVersion();
        } else {
            return config.getHighestProtocolVersion();
        }
    }

    @Override
    public boolean isClientAuthentication() {
        if (context.getTlsContext().isClientAuthentication() != null) {
            return context.getTlsContext().isClientAuthentication();
        } else {
            return config.isClientAuthentication();
        }
    }

    @Override
    public byte[] getLastHandledApplicationMessageData() {
        if (context.getTlsContext().getLastHandledApplicationMessageData() != null) {
            return copy(context.getTlsContext().getLastHandledApplicationMessageData());
        } else {
            return config.getDefaultApplicationMessageData().getBytes(StandardCharsets.ISO_8859_1);
        }
    }

    @Override
    public byte[] getPsk() {
        if (context.getTlsContext().getPsk() != null) {
            return copy(context.getTlsContext().getPsk());
        } else {
            return config.getPsk();
        }
    }

    @Override
    public String getHttpCookieValue() {
        String cookieVal = context.getHttpContext().getHttpCookieValue();
        if (cookieVal != null && !cookieVal.isEmpty()) {
            return cookieVal;
        } else {
            return config.getDefaultHttpCookieValue();
        }
    }

    @Override
    public String getHttpCookieName() {
        String cookieName = context.getHttpContext().getHttpCookieName();
        if (cookieName != null && !cookieName.isEmpty()) {
            return cookieName;
        } else {
            return config.getDefaultHttpCookieName();
        }
    }

    @Override
    public List<PskSet> getPskSets() {
        if (context.getTlsContext().getPskSets() != null) {
            return context.getTlsContext().getPskSets();
        } else {
            return config.getDefaultPskSets();
        }
    }

    @Override
    public CipherSuite getEarlyDataCipherSuite() {
        if (context.getTlsContext().getEarlyDataCipherSuite() != null) {
            return context.getTlsContext().getEarlyDataCipherSuite();
        } else {
            return config.getEarlyDataCipherSuite();
        }
    }

    @Override
    public byte[] getClientEarlyTrafficSecret() {
        if (context.getTlsContext().getClientEarlyTrafficSecret() != null) {
            return copy(context.getTlsContext().getClientEarlyTrafficSecret());
        } else {
            return config.getClientEarlyTrafficSecret();
        }
    }

    @Override
    public byte[] getEarlySecret() {
        if (context.getTlsContext().getEarlySecret() != null) {
            return copy(context.getTlsContext().getEarlySecret());
        } else {
            return config.getEarlySecret();
        }
    }

    @Override
    public byte[] getEarlyDataPsk() {
        if (context.getTlsContext().getEarlyDataPsk() != null) {
            return copy(context.getTlsContext().getEarlyDataPsk());
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
        if (context.getTlsContext().getClientKeyShareStoreEntryList() != null) {
            return context.getTlsContext().getClientKeyShareStoreEntryList();
        } else {
            return config.getDefaultClientKeyStoreEntries();
        }
    }

    @Override
    public KeyShareStoreEntry getServerKeyShare() {
        if (context.getTlsContext().getServerKeyShareStoreEntry() != null) {
            return context.getTlsContext().getServerKeyShareStoreEntry();
        } else {
            return config.getDefaultServerKeyShareEntry();
        }
    }

    @Override
    public byte[] getHandshakeSecret() {
        if (context.getTlsContext().getHandshakeSecret() != null) {
            return copy(context.getTlsContext().getHandshakeSecret());
        } else {
            return config.getDefaultHandshakeSecret();
        }
    }

    private byte[] copy(byte[] array) {
        return Arrays.copyOf(array, array.length);
    }

    @Override
    public String getClientPWDUsername() {
        if (context.getTlsContext().getClientPWDUsername() != null) {
            return context.getTlsContext().getClientPWDUsername();
        } else {
            return config.getDefaultClientPWDUsername();
        }
    }

    @Override
    public byte[] getServerPWDSalt() {
        if (context.getTlsContext().getServerPWDSalt() != null) {
            return context.getTlsContext().getServerPWDSalt();
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
        if (context.getTlsContext().getEsniClientNonce() != null) {
            return this.context.getTlsContext().getEsniClientNonce();
        } else {
            return config.getDefaultEsniClientNonce();
        }
    }

    @Override
    public byte[] getEsniServerNonce() {
        if (context.getTlsContext().getEsniServerNonce() != null) {
            return this.context.getTlsContext().getEsniServerNonce();
        } else {
            return config.getDefaultEsniServerNonce();
        }
    }

    @Override
    public byte[] getEsniRecordBytes() {
        if (context.getTlsContext().getEsniRecordBytes() != null) {
            return context.getTlsContext().getEsniRecordBytes();
        } else {
            return config.getDefaultEsniRecordBytes();
        }
    }

    @Override
    public EsniDnsKeyRecordVersion getEsniRecordVersion() {
        if (context.getTlsContext().getEsniRecordVersion() != null) {
            return context.getTlsContext().getEsniRecordVersion();
        } else {
            return config.getDefaultEsniRecordVersion();
        }
    }

    @Override
    public byte[] getEsniRecordChecksum() {
        if (context.getTlsContext().getEsniRecordChecksum() != null) {
            return context.getTlsContext().getEsniRecordChecksum();
        } else {
            return config.getDefaultEsniRecordChecksum();
        }
    }

    @Override
    public List<KeyShareStoreEntry> getEsniServerKeyShareEntries() {
        if (context.getTlsContext().getEsniServerKeyShareEntries() != null
                && !context.getTlsContext().getEsniServerKeyShareEntries().isEmpty()) {
            return context.getTlsContext().getEsniServerKeyShareEntries();
        } else {
            return config.getDefaultEsniServerKeyShareEntries();
        }
    }

    @Override
    public List<CipherSuite> getEsniServerCipherSuites() {
        if (context.getTlsContext().getEsniServerCipherSuites() != null) {
            return context.getTlsContext().getEsniServerCipherSuites();
        } else {
            return config.getDefaultEsniServerCipherSuites();
        }
    }

    @Override
    public Integer getEsniPaddedLength() {
        if (context.getTlsContext().getEsniPaddedLength() != null) {
            return context.getTlsContext().getEsniPaddedLength();
        } else {
            return config.getDefaultEsniPaddedLength();
        }
    }

    @Override
    public Long getEsniNotBefore() {
        if (context.getTlsContext().getEsniKeysNotBefore() != null) {
            return this.context.getTlsContext().getEsniKeysNotBefore();
        } else {
            return config.getDefaultEsniNotBefore();
        }
    }

    @Override
    public Long getEsniNotAfter() {
        if (context.getTlsContext().getEsniNotAfter() != null) {
            return context.getTlsContext().getEsniNotAfter();
        } else {
            return config.getDefaultEsniNotAfter();
        }
    }

    @Override
    public List<String> getProposedAlpnProtocols() {
        if (context.getTlsContext().getProposedAlpnProtocols() != null) {
            return context.getTlsContext().getProposedAlpnProtocols();
        } else {
            return config.getDefaultProposedAlpnProtocols();
        }
    }

    @Override
    public Integer getMaxEarlyDataSize() {
        if (context.getTlsContext().getMaxEarlyDataSize() != null) {
            return context.getTlsContext().getMaxEarlyDataSize();
        } else {
            return config.getDefaultMaxEarlyDataSize();
        }
    }

    @Override
    public byte[] getLastClientHello() {
        if (context.getTlsContext().getLastClientHello() != null) {
            return context.getTlsContext().getLastClientHello();
        } else {
            return config.getDefaultLastClientHello();
        }
    }

    @Override
    public byte[] getExtensionCookie() {
        if (context.getTlsContext().getExtensionCookie() != null) {
            return context.getTlsContext().getExtensionCookie();
        } else {
            return config.getDefaultExtensionCookie();
        }
    }

    @Override
    public BigInteger getServerEphemeralDhModulus() {
        if (context.getTlsContext().getServerEphemeralDhModulus() != null) {
            return context.getTlsContext().getServerEphemeralDhModulus();
        } else {
            return config.getDefaultServerEphemeralDhModulus();
        }
    }

    @Override
    public BigInteger getServerEphemeralDhGenerator() {
        if (context.getTlsContext().getServerEphemeralDhGenerator() != null) {
            return context.getTlsContext().getServerEphemeralDhGenerator();
        } else {
            return config.getDefaultServerEphemeralDhGenerator();
        }
    }

    @Override
    public BigInteger getServerEphemeralDhPrivateKey() {
        if (context.getTlsContext().getServerEphemeralDhPrivateKey() != null) {
            return context.getTlsContext().getServerEphemeralDhPrivateKey();
        } else {
            return config.getDefaultServerEphemeralDhPrivateKey();
        }
    }

    @Override
    public BigInteger getClientEphemeralDhPrivateKey() {
        if (context.getTlsContext().getClientEphemeralDhPrivateKey() != null) {
            return context.getTlsContext().getClientEphemeralDhPrivateKey();
        } else {
            return config.getDefaultClientEphemeralDhPrivateKey();
        }
    }

    @Override
    public BigInteger getServerEphemeralDhPublicKey() {
        if (context.getTlsContext().getServerEphemeralDhPublicKey() != null) {
            return context.getTlsContext().getServerEphemeralDhPublicKey();
        } else {
            return config.getDefaultServerEphemeralDhPublicKey();
        }
    }

    @Override
    public BigInteger getClientEphemeralDhPublicKey() {
        if (context.getTlsContext().getClientEphemeralDhPublicKey() != null) {
            return context.getTlsContext().getClientEphemeralDhPublicKey();
        } else {
            return config.getDefaultClientEphemeralDhPublicKey();
        }
    }

    @Override
    public BigInteger getServerEphemeralEcPrivateKey() {
        if (context.getTlsContext().getServerEphemeralEcPrivateKey() != null) {
            return context.getTlsContext().getServerEphemeralEcPrivateKey();
        } else {
            return config.getDefaultServerEphemeralEcPrivateKey();
        }
    }

    @Override
    public BigInteger getClientEphemeralEcPrivateKey() {
        if (context.getTlsContext().getClientEphemeralEcPrivateKey() != null) {
            return context.getTlsContext().getClientEphemeralEcPrivateKey();
        } else {
            return config.getDefaultClientEphemeralEcPrivateKey();
        }
    }

    @Override
    public Point getClientEphemeralEcPublicKey() {
        if (context.getTlsContext().getClientEphemeralEcPublicKey() != null) {
            return context.getTlsContext().getClientEphemeralEcPublicKey();
        } else {
            return config.getDefaultClientEphemeralEcPublicKey();
        }
    }

    @Override
    public Point getServerEphemeralEcPublicKey() {
        if (context.getTlsContext().getServerEphemeralEcPublicKey() != null) {
            return context.getTlsContext().getServerEphemeralEcPublicKey();
        } else {
            return config.getDefaultServerEphemeralEcPublicKey();
        }
    }

    @Override
    public BigInteger getServerEphemeralRsaExportModulus() {
        if (context.getTlsContext().getServerEphemeralRsaExportModulus() != null) {
            return context.getTlsContext().getServerEphemeralRsaExportModulus();
        } else {
            return config.getDefaultServerEphemeralRsaExportModulus();
        }
    }

    @Override
    public BigInteger getServerEphemeralRsaExportPublicKey() {
        if (context.getTlsContext().getServerEphemeralRsaExportPublicKey() != null) {
            return context.getTlsContext().getServerEphemeralRsaExportPublicKey();
        } else {
            return config.getDefaultServerEphemeralRsaExportPublicKey();
        }
    }

    @Override
    public BigInteger getServerEphemeralRsaExportPrivateKey() {
        if (context.getTlsContext().getServerEphemeralRsaExportPrivateKey() != null) {
            return context.getTlsContext().getServerEphemeralRsaExportPrivateKey();
        } else {
            return config.getDefaultServerEphemeralRsaExportPrivateKey();
        }
    }

    @Override
    public BigInteger getRsaKeyExchangePublicExponent() {
        return getServerX509Chooser().getSubjectRsaPublicExponent();
    }

    @Override
    public BigInteger getRsaKeyExchangeModulus() {
        return getServerX509Chooser().getSubjectRsaModulus();
    }

    @Override
    public BigInteger getRsaKeyExchangePrivateKey() {
        return getServerX509Chooser().getSubjectRsaPrivateKey();
    }

    @Override
    public BigInteger getDhKeyExchangePeerPublicKey() {
        KeyExchangeAlgorithm algorithm = getSelectedCipherSuite().getKeyExchangeAlgorithm();
        if (algorithm != null && algorithm.isKeyExchangeStaticDh()) {
            return context.getTlsContext()
                    .getPeerX509Context()
                    .getChooser()
                    .getSubjectDhPublicKey();
        } else {
            if (getConnectionEndType() == ConnectionEndType.CLIENT) {
                return getServerEphemeralDhPublicKey();
            } else {
                return getClientEphemeralDhPublicKey();
            }
        }
    }

    @Override
    public BigInteger getDhKeyExchangeModulus() {
        KeyExchangeAlgorithm algorithm = getSelectedCipherSuite().getKeyExchangeAlgorithm();
        if (algorithm != null && algorithm.isKeyExchangeStaticDh()) {
            return context.getTlsContext().getPeerX509Context().getChooser().getSubjectDhModulus();
        } else {
            return getServerEphemeralDhModulus();
        }
    }

    @Override
    public BigInteger getDhKeyExchangeGenerator() {
        KeyExchangeAlgorithm algorithm = getSelectedCipherSuite().getKeyExchangeAlgorithm();
        if (algorithm != null && algorithm.isKeyExchangeStaticDh()) {
            return context.getTlsContext()
                    .getPeerX509Context()
                    .getChooser()
                    .getSubjectDhGenerator();
        } else {
            return getServerEphemeralDhGenerator();
        }
    }

    @Override
    public BigInteger getDhKeyExchangePrivateKey() {
        KeyExchangeAlgorithm algorithm = getSelectedCipherSuite().getKeyExchangeAlgorithm();
        if (algorithm != null && algorithm.isKeyExchangeStaticDh()) {
            return context.getTlsContext()
                    .getTalkingX509Context()
                    .getChooser()
                    .getSubjectDhPrivateKey();
        } else {
            if (getConnectionEndType() == ConnectionEndType.CLIENT) {
                return getClientEphemeralDhPrivateKey();
            } else {
                return getServerEphemeralDhPrivateKey();
            }
        }
    }

    @Override
    public Point getEcKeyExchangePeerPublicKey() {
        KeyExchangeAlgorithm algorithm = getSelectedCipherSuite().getKeyExchangeAlgorithm();
        if (algorithm != null && algorithm.isKeyExchangeStaticEcdh()) {
            return context.getTlsContext()
                    .getPeerX509Context()
                    .getChooser()
                    .getSubjectEcPublicKey();
        } else {
            if (getConnectionEndType() == ConnectionEndType.CLIENT) {
                return getServerEphemeralEcPublicKey();
            } else {
                return getClientEphemeralEcPublicKey();
            }
        }
    }

    @Override
    public BigInteger getEcKeyExchangePrivateKey() {
        KeyExchangeAlgorithm algorithm = getSelectedCipherSuite().getKeyExchangeAlgorithm();
        if (algorithm != null && algorithm.isKeyExchangeStaticEcdh()) {
            return context.getTlsContext()
                    .getTalkingX509Context()
                    .getChooser()
                    .getSubjectEcPrivateKey();
        } else {
            if (getConnectionEndType() == ConnectionEndType.CLIENT) {
                return getClientEphemeralEcPrivateKey();
            } else {
                return getServerEphemeralEcPrivateKey();
            }
        }
    }

    @Override
    public BigInteger getKeySharePrivateKey(NamedGroup keyStoreGroup) {
        if (keyStoreGroup.isDhGroup()) {
            if (getConnectionEndType() == ConnectionEndType.CLIENT) {
                return getClientEphemeralDhPrivateKey();
            } else {
                return getServerEphemeralDhPrivateKey();
            }
        } else {
            if (getConnectionEndType() == ConnectionEndType.CLIENT) {
                return getClientEphemeralEcPrivateKey();
            } else {
                return getServerEphemeralEcPrivateKey();
            }
        }
    }

    @Override
    public Integer getPeerReceiveLimit() {
        if (context.getTlsContext().getPeerReceiveLimit() != null) {
            return context.getTlsContext().getPeerReceiveLimit();
        } else {
            return config.getDefaultAssumedMaxReceiveLimit();
        }
    }

    @Override
    public EchConfig getEchConfig() {
        if (context != null && context.getTlsContext().getEchConfig() != null) {
            return context.getTlsContext().getEchConfig();
        } else {
            return config.getDefaultEchConfig();
        }
    }

    @Override
    public KeyShareEntry getEchClientKeyShareEntry() {
        if (context != null && context.getTlsContext().getEchClientKeyShareEntry() != null) {
            return context.getTlsContext().getEchClientKeyShareEntry();
        } else {
            KeyShareEntry keyShareEntry = new KeyShareEntry();
            keyShareEntry.setPrivateKey(config.getDefaultEchClientPrivateKey());
            KeyShareEntryPreparator keyShareEntryPreparator =
                    new KeyShareEntryPreparator(this, keyShareEntry);
            keyShareEntry.setGroupConfig(getEchConfig().getKem().getNamedGroup());
            keyShareEntryPreparator.prepare();
            if (context != null) {
                context.getTlsContext().setEchClientKeyShareEntry(keyShareEntry);
            }
            return keyShareEntry;
        }
    }

    @Override
    public KeyShareEntry getEchServerKeyShareEntry() {
        if (context != null
                && context.getTlsContext() != null
                && context.getTlsContext().getEchClientKeyShareEntry() != null) {
            return context.getTlsContext().getEchServerKeyShareEntry();
        } else {
            KeyShareEntry keyShareEntry = new KeyShareEntry();
            keyShareEntry.setPrivateKey(config.getDefaultEchServerPrivateKey());
            KeyShareEntryPreparator keyShareEntryPreparator =
                    new KeyShareEntryPreparator(this, keyShareEntry);
            keyShareEntry.setGroupConfig(getEchConfig().getKem().getNamedGroup());
            keyShareEntryPreparator.prepare();
            if (context != null) {
                context.getTlsContext().setEchServerKeyShareEntry(keyShareEntry);
            }
            return keyShareEntry;
        }
    }

    @Override
    public Integer getNumberOfRequestedConnectionIds() {
        if (context.getTlsContext().getNumberOfRequestedConnectionIds() != null) {
            return context.getTlsContext().getNumberOfRequestedConnectionIds();
        } else {
            return config.getDefaultNumberOfRequestedConnectionIds();
        }
    }

    @Override
    public SrtpProtectionProfile getSelectedSrtpProtectionProfile() {
        if (context.getTlsContext().getSelectedSrtpProtectionProfile() != null) {
            return context.getTlsContext().getSelectedSrtpProtectionProfile();
        } else {
            return config.getDefaultSelectedSrtpProtectionProfile();
        }
    }
}
