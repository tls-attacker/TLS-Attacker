/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.util.List;

public abstract class Chooser {

    protected final Context context;

    protected final Config config;

    public Chooser(Context context, Config config) {
        this.config = config;
        this.context = context;
    }

    public Config getConfig() {
        return config;
    }

    public Context getContext() {
        return context;
    }

    public abstract List<ECPointFormat> getClientSupportedPointFormats();

    public abstract SignatureAndHashAlgorithm getSelectedSigHashAlgorithm();

    public abstract List<NamedGroup> getClientSupportedNamedGroups();

    public abstract List<NamedGroup> getServerSupportedNamedGroups();

    public abstract List<ECPointFormat> getServerSupportedPointFormats();

    public abstract List<SignatureAndHashAlgorithm> getClientSupportedSignatureAndHashAlgorithms();

    public abstract List<SignatureAndHashAlgorithm> getClientSupportedCertificateSignAlgorithms();

    public abstract ProtocolVersion getLastRecordVersion();

    public abstract byte[] getDistinguishedNames();

    public abstract List<ClientCertificateType> getClientCertificateTypes();

    public abstract MaxFragmentLength getMaxFragmentLength();

    public abstract Integer getMaxEarlyDataSize();

    public abstract HeartbeatMode getHeartbeatMode();

    public abstract boolean isUseExtendedMasterSecret();

    public abstract List<CompressionMethod> getClientSupportedCompressions();

    public abstract List<CipherSuite> getClientSupportedCipherSuites();

    public abstract List<SignatureAndHashAlgorithm> getServerSupportedSignatureAndHashAlgorithms();

    public abstract List<SignatureAndHashAlgorithm> getServerSupportedCertificateSignAlgorithms();

    public abstract ProtocolVersion getSelectedProtocolVersion();

    public abstract ProtocolVersion getHighestClientProtocolVersion();

    public abstract ConnectionEndType getTalkingConnectionEnd();

    public abstract byte[] getMasterSecret();

    public abstract CipherSuite getSelectedCipherSuite();

    public abstract SSL2CipherSuite getSSL2CipherSuite();

    public abstract byte[] getPreMasterSecret();

    public abstract byte[] getClientExtendedRandom();

    public abstract byte[] getServerExtendedRandom();

    public abstract byte[] getClientRandom();

    public abstract ClientHelloMessage getInnerClientHello();

    public abstract byte[] getServerRandom();

    public abstract CompressionMethod getSelectedCompressionMethod();

    public abstract byte[] getClientSessionId();

    public abstract byte[] getServerSessionId();

    public abstract byte[] getDtlsCookie();

    public abstract byte[] getExtensionCookie();

    public abstract TransportHandler getTransportHandler();

    public abstract PRFAlgorithm getPRFAlgorithm();

    public abstract byte[] getLatestSessionTicket();

    public abstract byte[] getSignedCertificateTimestamp();

    public abstract TokenBindingVersion getTokenBindingVersion();

    public abstract List<TokenBindingKeyParameters> getTokenBindingKeyParameters();

    public abstract BigInteger getServerDhModulus();

    public abstract BigInteger getServerDhGenerator();

    public abstract BigInteger getClientDhModulus();

    public abstract BigInteger getClientDhGenerator();

    public abstract BigInteger getServerDhPrivateKey();

    public abstract BigInteger getClientDhPrivateKey();

    public abstract BigInteger getServerDhPublicKey();

    public abstract BigInteger getClientDhPublicKey();

    public abstract GOSTCurve getSelectedGostCurve();

    public abstract BigInteger getSRPModulus();

    public abstract BigInteger getPSKModulus();

    public abstract byte[] getPSKIdentity();

    public abstract byte[] getPSKIdentityHint();

    public abstract BigInteger getPSKServerPrivateKey();

    public abstract BigInteger getPSKServerPublicKey();

    public abstract BigInteger getPSKGenerator();

    public abstract BigInteger getSRPGenerator();

    public abstract BigInteger getSRPServerPrivateKey();

    public abstract BigInteger getSRPServerPublicKey();

    public abstract BigInteger getSRPClientPrivateKey();

    public abstract BigInteger getSRPClientPublicKey();

    public abstract byte[] getSRPServerSalt();

    public abstract byte[] getSRPPassword();

    public abstract byte[] getSRPIdentity();

    public abstract BigInteger getServerEcPrivateKey();

    public abstract BigInteger getClientEcPrivateKey();

    public abstract NamedGroup getSelectedNamedGroup();

    public abstract NamedGroup getEcCertificateCurve();

    public abstract Point getClientEcPublicKey();

    public abstract Point getServerEcPublicKey();

    public abstract EllipticCurveType getEcCurveType();

    public abstract BigInteger getClientRsaModulus();

    public abstract BigInteger getServerRsaModulus();

    public abstract BigInteger getServerRSAPublicKey();

    public abstract BigInteger getClientRSAPublicKey();

    public abstract byte[] getCertificateRequestContext();

    public abstract byte[] getServerHandshakeTrafficSecret();

    public abstract byte[] getClientHandshakeTrafficSecret();

    public abstract byte[] getClientApplicationTrafficSecret();

    public abstract byte[] getServerApplicationTrafficSecret();

    public abstract BigInteger getClientRSAPrivateKey();

    public abstract BigInteger getServerRSAPrivateKey();

    public abstract Connection getConnection();

    public abstract ConnectionEndType getConnectionEndType();

    public abstract ConnectionEndType getMyConnectionPeer();

    public abstract ProtocolVersion getHighestProtocolVersion();

    public abstract boolean isClientAuthentication();

    public abstract byte[] getLastHandledApplicationMessageData();

    public abstract CertificateType getSelectedClientCertificateType();

    public abstract CertificateType getSelectedServerCertificateType();

    public abstract String getHttpCookieName();

    public abstract String getHttpCookieValue();

    public abstract byte[] getPsk();

    public abstract List<PskSet> getPskSets();

    public abstract CipherSuite getEarlyDataCipherSuite();

    public abstract byte[] getClientEarlyTrafficSecret();

    public abstract byte[] getEarlySecret();

    public abstract byte[] getEarlyDataPsk();

    public abstract List<KeyShareStoreEntry> getClientKeyShares();

    public abstract KeyShareStoreEntry getServerKeyShare();

    public abstract BigInteger getDsaClientPublicKey();

    public abstract BigInteger getDsaClientPrivateKey();

    public abstract BigInteger getDsaClientPrimeP();

    public abstract BigInteger getDsaClientPrimeQ();

    public abstract BigInteger getDsaClientGenerator();

    public abstract BigInteger getDsaServerPublicKey();

    public abstract BigInteger getDsaServerPrivateKey();

    public abstract BigInteger getDsaServerPrimeP();

    public abstract BigInteger getDsaServerPrimeQ();

    public abstract BigInteger getDsaServerGenerator();

    public abstract byte[] getHandshakeSecret();

    public abstract String getClientPWDUsername();

    public abstract byte[] getServerPWDSalt();

    public abstract String getPWDPassword();

    public abstract byte[] getEsniClientNonce();

    public abstract byte[] getEsniServerNonce();

    public abstract byte[] getEsniRecordBytes();

    public abstract EsniDnsKeyRecordVersion getEsniRecordVersion();

    public abstract byte[] getEsniRecordChecksum();

    public abstract List<KeyShareStoreEntry> getEsniServerKeyShareEntries();

    public abstract List<CipherSuite> getEsniServerCipherSuites();

    public abstract Integer getEsniPaddedLength();

    public abstract Long getEsniNotBefore();

    public abstract Long getEsniNotAfter();

    public abstract List<String> getProposedAlpnProtocols();

    public abstract byte[] getLastClientHello();

    public abstract Integer getOutboundRecordSizeLimit();

    public abstract Integer getInboundRecordSizeLimit();

    public abstract Integer getOutboundMaxRecordDataSize();

    public abstract Integer getInboundMaxRecordDataSize();

    public abstract EchConfig getEchConfig();

    public abstract KeyShareEntry getEchClientKeyShareEntry();

    public abstract KeyShareEntry getEchServerKeyShareEntry();
}
