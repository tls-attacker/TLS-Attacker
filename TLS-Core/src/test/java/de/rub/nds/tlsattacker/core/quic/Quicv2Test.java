/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.NoSuchPaddingException;
import org.junit.Test;

public class Quicv2Test {

    @Test
    public void versionDependentInitialSecretsTest()
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        // Check that we generate the correct version-dependent initial secrets
        QuicContext quicv1Context = calculateInitialSecretsForVersion(QuicVersion.VERSION_1);

        assert Arrays.equals(
                quicv1Context.getInitialSalt(),
                new byte[] {
                    0x38,
                    0x76,
                    0x2c,
                    (byte) 0xf7,
                    (byte) 0xf5,
                    0x59,
                    0x34,
                    (byte) 0xb3,
                    0x4d,
                    0x17,
                    (byte) 0x9a,
                    (byte) 0xe6,
                    (byte) 0xa4,
                    (byte) 0xc8,
                    0x0c,
                    (byte) 0xad,
                    (byte) 0xcc,
                    (byte) 0xbb,
                    0x7f,
                    0x0a
                });
        assert Arrays.equals(
                quicv1Context.getInitialSecret(),
                new byte[] {
                    (byte) 0xe4,
                    0x1d,
                    0x1a,
                    0x39,
                    (byte) 0xcb,
                    (byte) 0xb6,
                    0x37,
                    0x02,
                    0x5d,
                    0x7f,
                    0x57,
                    (byte) 0xf6,
                    0x06,
                    0x56,
                    (byte) 0xd5,
                    0x0b,
                    0x30,
                    (byte) 0xd7,
                    0x1f,
                    0x62,
                    0x71,
                    (byte) 0xe9,
                    (byte) 0xf3,
                    (byte) 0xd5,
                    0x68,
                    0x7f,
                    (byte) 0xf4,
                    0x55,
                    0x6c,
                    (byte) 0xca,
                    0x69,
                    (byte) 0xeb
                });

        QuicContext quicv2Context = calculateInitialSecretsForVersion(QuicVersion.VERSION_2);

        assert Arrays.equals(
                quicv2Context.getInitialSalt(),
                new byte[] {
                    0x0d,
                    (byte) 0xed,
                    (byte) 0xe3,
                    (byte) 0xde,
                    (byte) 0xf7,
                    0x00,
                    (byte) 0xa6,
                    (byte) 0xdb,
                    (byte) 0x81,
                    (byte) 0x93,
                    (byte) 0x81,
                    (byte) 0xbe,
                    0x6e,
                    0x26,
                    (byte) 0x9d,
                    (byte) 0xcb,
                    (byte) 0xf9,
                    (byte) 0xbd,
                    0x2e,
                    (byte) 0xd9
                });
        assert Arrays.equals(
                quicv2Context.getInitialSecret(),
                new byte[] {
                    (byte) 0xdc,
                    0x59,
                    0x19,
                    (byte) 0x8d,
                    0x08,
                    (byte) 0xf2,
                    (byte) 0xde,
                    (byte) 0xa6,
                    (byte) 0x9f,
                    0x55,
                    (byte) 0xbb,
                    0x1d,
                    0x07,
                    0x62,
                    0x2f,
                    (byte) 0xd0,
                    (byte) 0xee,
                    (byte) 0x9c,
                    0x0e,
                    0x5a,
                    (byte) 0xca,
                    0x34,
                    0x49,
                    0x77,
                    (byte) 0xee,
                    0x0d,
                    0x20,
                    (byte) 0x99,
                    (byte) 0xd5,
                    (byte) 0xbe,
                    (byte) 0xfd,
                    (byte) 0xdb
                });

        // And check that we do not generate any secrets for "pseudo-versions"
        try {
            calculateInitialSecretsForVersion(QuicVersion.NEGOTIATION_VERSION);
            assert false;
        } catch (UnsupportedOperationException e) {
            // This exception is what we expect
        }
        try {
            calculateInitialSecretsForVersion(QuicVersion.NULL_VERSION);
            assert false;
        } catch (UnsupportedOperationException e) {
            // This exception is what we expect
        }
    }


    @Test
    public void versionDependent0RTTSecretsTest()
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        // Check that we generate the correct version-dependent initial secrets
        QuicContext quicv1Context = calculate0RTTSecretsForVersion(QuicVersion.VERSION_1);
        QuicContext quicv2Context = calculate0RTTSecretsForVersion(QuicVersion.VERSION_2);

        assert Arrays.equals(
                quicv1Context.getZeroRTTClientSecret(),
                quicv2Context.getZeroRTTClientSecret());

        // And check that we do not generate any secrets for "pseudo-versions"
        try {
            calculate0RTTSecretsForVersion(QuicVersion.NEGOTIATION_VERSION);
            assert false;
        } catch (UnsupportedOperationException e) {
            // This exception is what we expect
        }
        try {
            calculate0RTTSecretsForVersion(QuicVersion.NULL_VERSION);
            assert false;
        } catch (UnsupportedOperationException e) {
            // This exception is what we expect
        }
    }

    private QuicContext calculateInitialSecretsForVersion(QuicVersion version)
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        Config config = new Config();
        config.setQuicVersion(version);
        QuicContext context =
                new Context(new State(config), new InboundConnection()).getQuicContext();
        // Fix connection ID for secret calculation
        context.setFirstDestinationConnectionId(new byte[8]);
        // We only calculate the initial secrets for this test because the other secrets require
        // more context and these should already be version-dependent
        QuicPacketCryptoComputations.calculateInitialSecrets(context);
        return context;
    }
    private QuicContext calculate0RTTSecretsForVersion(QuicVersion version)
            throws NoSuchAlgorithmException, CryptoException, NoSuchPaddingException {
        Config config = new Config();
        config.setQuicVersion(version);
        Context context =
                new Context(new State(config), new InboundConnection());
        TlsContext tlsContext = context.getTlsContext();
        QuicContext quicContext = context.getQuicContext();
        tlsContext.setEarlyDataCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        tlsContext.setClientEarlyTrafficSecret(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
        // Fix connection ID for secret calculation
        quicContext.setFirstDestinationConnectionId(new byte[8]);
        // We only calculate the initial secrets for this test because the other secrets require
        // more context and these should already be version-dependent
        QuicPacketCryptoComputations.calculate0RTTSecrets(quicContext);
        return quicContext;
    }
}
