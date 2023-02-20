/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.x509attacker.chooser.X509Chooser;
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

    public X509Chooser getX509Chooser() {
        return context.getTlsContext().getX509Context().getChooser();
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

    public abstract BigInteger getServerEphemeralDhModulus();

    public abstract BigInteger getServerEphemeralDhGenerator();

    public abstract BigInteger getServerEphemeralDhPrivateKey();

    public abstract BigInteger getClientEphemeralDhPrivateKey();

    public abstract BigInteger getServerEphemeralDhPublicKey();

    public abstract BigInteger getClientEphemeralDhPublicKey();

    public abstract GOSTCurve getSelectedGostCurve();

    public abstract BigInteger getSRPModulus();

    public abstract byte[] getPSKIdentity();

    public abstract byte[] getPSKIdentityHint();

    public abstract BigInteger getSRPGenerator();

    public abstract BigInteger getSRPServerPrivateKey();

    public abstract BigInteger getSRPServerPublicKey();

    public abstract BigInteger getSRPClientPrivateKey();

    public abstract BigInteger getSRPClientPublicKey();

    public abstract byte[] getSRPServerSalt();

    public abstract byte[] getSRPPassword();

    public abstract byte[] getSRPIdentity();

    public abstract BigInteger getServerEphemeralEcPrivateKey();

    public abstract BigInteger getClientEphemeralEcPrivateKey();

    public abstract NamedGroup getSelectedNamedGroup();

    public abstract Point getClientEphemeralEcPublicKey();

    public abstract Point getServerEphemeralEcPublicKey();

    public abstract EllipticCurveType getEcCurveType();

    public abstract BigInteger getServerEphemeralRsaExportModulus();

    public abstract BigInteger getServerEphemeralRsaExportPublicKey();

    public abstract byte[] getCertificateRequestContext();

    public abstract byte[] getServerHandshakeTrafficSecret();

    public abstract byte[] getClientHandshakeTrafficSecret();

    public abstract byte[] getClientApplicationTrafficSecret();

    public abstract byte[] getServerApplicationTrafficSecret();

    public abstract BigInteger getServerEphemeralRsaExportPrivateKey();

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

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getRsaKeyExchangePublicExponent();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getRsaKeyExchangeModulus();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getRsaKeyExchangePrivateKey();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getDhKeyExchangePeerPublicKey();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getDhKeyExchangeModulus();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getDhKeyExchangeGenerator();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getDhKeyExchangePrivateKey();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract Point getEcKeyExchangePeerPublicKey();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @return
     */
    public abstract BigInteger getEcKeyExchangePrivateKey();

    /**
     * Always returns the correct value depending on the selected cipher suites
     *
     * @param keyStoreGroup
     * @return
     */
    public abstract BigInteger getKeySharePrivateKey(NamedGroup keyStoreGroup);
}
