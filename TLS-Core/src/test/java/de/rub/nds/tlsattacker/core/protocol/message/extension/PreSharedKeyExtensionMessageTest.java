/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class PreSharedKeyExtensionMessageTest {

    @Test
    public void testCopyPskSetsFromConfig() {
        // Create a config with PSK sets
        Config config = new Config();
        List<PskSet> pskSets = new ArrayList<>();

        PskSet pskSet1 =
                new PskSet(
                        new byte[] {0x01, 0x02}, // preSharedKeyIdentity
                        new byte[] {0x03, 0x04}, // preSharedKey
                        "test",
                        new byte[] {0x05, 0x06}, // ticketAge
                        new byte[] {0x07, 0x08}, // ticketAgeAdd
                        CipherSuite.TLS_AES_128_GCM_SHA256);

        PskSet pskSet2 =
                new PskSet(
                        new byte[] {0x11, 0x12}, // preSharedKeyIdentity
                        new byte[] {0x13, 0x14}, // preSharedKey
                        "test2",
                        new byte[] {0x15, 0x16}, // ticketAge
                        new byte[] {0x17, 0x18}, // ticketAgeAdd
                        CipherSuite.TLS_AES_256_GCM_SHA384);

        pskSets.add(pskSet1);
        pskSets.add(pskSet2);
        config.setDefaultPskSets(pskSets);

        // Create extension with config
        PreSharedKeyExtensionMessage extension = new PreSharedKeyExtensionMessage(config);

        // Verify identities were created correctly
        assertNotNull(extension.getIdentities());
        assertEquals(2, extension.getIdentities().size());

        // Verify the fix: identity field should be set
        PSKIdentity identity1 = extension.getIdentities().get(0);
        assertNotNull(identity1.getIdentity());
        assertNotNull(identity1.getIdentity().getValue());
        assertArrayEquals(new byte[] {0x01, 0x02}, identity1.getIdentity().getValue());
        assertArrayEquals(new byte[] {0x01, 0x02}, identity1.getIdentityConfig());

        PSKIdentity identity2 = extension.getIdentities().get(1);
        assertNotNull(identity2.getIdentity());
        assertNotNull(identity2.getIdentity().getValue());
        assertArrayEquals(new byte[] {0x11, 0x12}, identity2.getIdentity().getValue());
        assertArrayEquals(new byte[] {0x11, 0x12}, identity2.getIdentityConfig());

        // Verify binders were created
        assertNotNull(extension.getBinders());
        assertEquals(2, extension.getBinders().size());
    }

    @Test
    public void testCopyPskSetsWithLimitPsksToOne() {
        // Create a config with multiple PSK sets but limit to one
        Config config = new Config();
        config.setLimitPsksToOne(true);

        List<PskSet> pskSets = new ArrayList<>();

        PskSet pskSet1 =
                new PskSet(
                        new byte[] {0x01, 0x02}, // preSharedKeyIdentity
                        new byte[] {0x03, 0x04}, // preSharedKey
                        "test",
                        new byte[] {0x05, 0x06}, // ticketAge
                        new byte[] {0x07, 0x08}, // ticketAgeAdd
                        CipherSuite.TLS_AES_128_GCM_SHA256);

        PskSet pskSet2 =
                new PskSet(
                        new byte[] {0x11, 0x12}, // preSharedKeyIdentity
                        new byte[] {0x13, 0x14}, // preSharedKey
                        "test2",
                        new byte[] {0x15, 0x16}, // ticketAge
                        new byte[] {0x17, 0x18}, // ticketAgeAdd
                        CipherSuite.TLS_AES_256_GCM_SHA384);

        pskSets.add(pskSet1);
        pskSets.add(pskSet2);
        config.setDefaultPskSets(pskSets);

        // Create extension with config
        PreSharedKeyExtensionMessage extension = new PreSharedKeyExtensionMessage(config);

        // Verify only one identity was created
        assertNotNull(extension.getIdentities());
        assertEquals(1, extension.getIdentities().size());

        // Verify the fix: identity field should be set for the first PSK only
        PSKIdentity identity = extension.getIdentities().get(0);
        assertNotNull(identity.getIdentity());
        assertNotNull(identity.getIdentity().getValue());
        assertArrayEquals(new byte[] {0x01, 0x02}, identity.getIdentity().getValue());

        // Verify only one binder was created
        assertNotNull(extension.getBinders());
        assertEquals(1, extension.getBinders().size());
    }

    @Test
    public void testNoPskSetsInConfig() {
        // Create a config without PSK sets
        Config config = new Config();

        // Create extension with config
        PreSharedKeyExtensionMessage extension = new PreSharedKeyExtensionMessage(config);

        // Verify no identities or binders were created
        assertNotNull(extension.getIdentities());
        assertEquals(0, extension.getIdentities().size());
        assertNotNull(extension.getBinders());
        assertEquals(0, extension.getBinders().size());
    }
}
