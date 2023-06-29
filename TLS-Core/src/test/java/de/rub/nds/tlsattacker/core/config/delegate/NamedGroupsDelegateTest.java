/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.*;

import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.LinkedList;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class NamedGroupsDelegateTest extends AbstractDelegateTest<NamedGroupsDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new NamedGroupsDelegate());
    }

    /** Test of getPointFormats method, of class NamedGroupsDelegate. */
    @Test
    public void testGetPointFormats() {
        args = new String[2];
        args[0] = "-point_formats";
        args[1] = "ANSIX962_COMPRESSED_PRIME,UNCOMPRESSED";
        jcommander.parse(args);
        assertTrue(
                delegate.getPointFormats().contains(ECPointFormat.UNCOMPRESSED),
                "UNCOMPRESSED should get parsed correctly");
        assertTrue(
                delegate.getPointFormats().contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME),
                "ANSIX962_COMPRESSED_PRIME should get parsed correctly");
    }

    @Test
    public void testInvalidPointFormats() {
        args = new String[2];
        args[0] = "-point_formats";
        args[1] = "NOTAPOINTFORMAT"; // Not a correct
        // point format
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setPointFormats method, of class NamedGroupsDelegate. */
    @Test
    public void testSetPointFormats() {
        LinkedList<ECPointFormat> supportedPointFormats = new LinkedList<>();
        supportedPointFormats.add(ECPointFormat.UNCOMPRESSED);
        delegate.setPointFormats(supportedPointFormats);
        assertEquals(
                supportedPointFormats,
                delegate.getPointFormats(),
                "PointFormats setter is not working correctly");
    }

    /** Test of getNamedCurves method, of class NamedGroupsDelegate. */
    @Test
    public void testGetNamedCurves() {
        args = new String[2];
        args[0] = "-named_group";
        args[1] = "SECP192R1,SECP256R1";
        jcommander.parse(args);
        assertTrue(
                delegate.getNamedGroups().contains(NamedGroup.SECP192R1),
                "SECP192R1 should get parsed correctly");
        assertTrue(
                delegate.getNamedGroups().contains(NamedGroup.SECP256R1),
                "SECP256R1 should get parsed correctly");
    }

    @Test
    public void testInvalidCurves() {
        args = new String[2];
        args[0] = "-named_group";
        args[1] = "NOTACURVE"; // Not a correct
        // Curve
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setNamedCurves method, of class NamedGroupsDelegate. */
    @Test
    public void testSetNamedCurves() {
        LinkedList<NamedGroup> supportedNamedCurves = new LinkedList<>();
        supportedNamedCurves.add(NamedGroup.BRAINPOOLP384R1);
        delegate.setNamedGroups(supportedNamedCurves);
        assertEquals(
                supportedNamedCurves,
                delegate.getNamedGroups(),
                "NamedCurves setter is not working correctly");
    }

    /** Test of applyDelegate method, of class NamedGroupsDelegate. */
    @Test
    public void testApplyDelegate() {
        args = new String[4];
        args[0] = "-named_group";
        args[1] = "SECP192R1,SECP256R1";
        args[2] = "-point_formats";
        args[3] = "ANSIX962_COMPRESSED_PRIME,UNCOMPRESSED";
        Config config = Config.createConfig();
        config.setDefaultSelectedNamedGroup(NamedGroup.SECP192R1);
        config.setDefaultClientSupportedPointFormats();
        config.setDefaultServerSupportedPointFormats();
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(
                config.getDefaultClientNamedGroups().contains(NamedGroup.SECP192R1),
                "SECP192R1 should get parsed correctly");
        assertTrue(
                config.getDefaultClientNamedGroups().contains(NamedGroup.SECP192R1),
                "SECP256R1 should get parsed correctly");
        assertTrue(
                config.getDefaultClientSupportedPointFormats().contains(ECPointFormat.UNCOMPRESSED),
                "UNCOMPRESSED should get parsed correctly");
        assertTrue(
                config.getDefaultClientSupportedPointFormats()
                        .contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME),
                "ANSIX962_COMPRESSED_PRIME should get parsed correctly");
        assertTrue(
                config.getDefaultServerSupportedPointFormats().contains(ECPointFormat.UNCOMPRESSED),
                "UNCOMPRESSED should get parsed correctly");
        assertTrue(
                config.getDefaultServerSupportedPointFormats()
                        .contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME),
                "ANSIX962_COMPRESSED_PRIME should get parsed correctly");
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
