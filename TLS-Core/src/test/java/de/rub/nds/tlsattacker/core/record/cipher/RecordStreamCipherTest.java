/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class RecordStreamCipherTest {

    private TlsContext context;

    public RecordStreamCipherTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();
    }

    // TODO check why cipher.contains("WITH_NULL") in
    // AlgorithmResolver.getCipherType(suite) is always assocaited with STREAM
    @Test
    public void testConstructors() throws NoSuchAlgorithmException, CryptoException {
        // This test just checks that the init() method will not break
        context.setClientRandom(new byte[] { 0 });
        context.setServerRandom(new byte[] { 0 });
        context.setMasterSecret(new byte[] { 0 });
        AliasedConnection[] connections = new AliasedConnection[] { new InboundConnection(), new OutboundConnection() };
        for (CipherSuite suite : CipherSuite.values()) {
            if (!suite.isGrease() && !suite.isSCSV() && !suite.name().contains("WITH_NULL_NULL")
                    && !suite.name().contains("CHACHA20_POLY1305") && !suite.name().contains("RABBIT")
                    && AlgorithmResolver.getCipherType(suite) == CipherType.STREAM
                    && !suite.name().contains("FORTEZZA") && !suite.name().contains("ARIA")) {
                context.setSelectedCipherSuite(suite);
                for (AliasedConnection con : connections) {
                    context.setConnection(con);
                    for (ProtocolVersion version : ProtocolVersion.values()) {
                        if (version == ProtocolVersion.SSL2 || version.isTLS13()) {
                            continue;
                        }
                        if (!suite.isSupportedInProtocol(version)) {
                            continue;
                        }
                        context.setSelectedProtocolVersion(version);
                        @SuppressWarnings("unused")
                        RecordStreamCipher cipher = new RecordStreamCipher(context,
                                KeySetGenerator.generateKeySet(context));
                    }
                }
            }
        }
    }

}
