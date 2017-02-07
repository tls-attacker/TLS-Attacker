/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.tls.config.converters.PointFormatConverter;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class EllipticCurveDelegateTest {

    private EllipticCurveDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public EllipticCurveDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new EllipticCurveDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getPointFormats method, of class EllipticCurveDelegate.
     */
    @Test
    public void testGetPointFormats() {
        args = new String[2];
        args[0] = "-point_formats";
        args[1] = "ANSIX962_COMPRESSED_PRIME,UNCOMPRESSED";
        jcommander.parse(args);
        assertTrue("UNCOMPRESSED should get parsed correctly",
                delegate.getPointFormats().contains(ECPointFormat.UNCOMPRESSED));
        assertTrue("ANSIX962_COMPRESSED_PRIME should get parsed correctly",
                delegate.getPointFormats().contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME));
    }

    @Test(expected = ParameterException.class)
    public void testInvalidPointFormats() {
        args = new String[2];
        args[0] = "-point_formats";
        args[1] = "NOTAPOINTFORMAT"; // Not a correct
        // point format
        jcommander.parse(args);
    }

    /**
     * Test of setPointFormats method, of class EllipticCurveDelegate.
     */
    @Test
    public void testSetPointFormats() {
        LinkedList<ECPointFormat> supportedPointFormats = new LinkedList<>();
        supportedPointFormats.add(ECPointFormat.UNCOMPRESSED);
        delegate.setPointFormats(supportedPointFormats);
        assertTrue("PointFormats setter is not working correctly",
                delegate.getPointFormats().equals(supportedPointFormats));
    }

    /**
     * Test of getNamedCurves method, of class EllipticCurveDelegate.
     */
    @Test
    public void testGetNamedCurves() {
        args = new String[2];
        args[0] = "-named_curve";
        args[1] = "SECP192R1,SECP256R1";
        jcommander.parse(args);
        assertTrue("SECP192R1 should get parsed correctly", delegate.getNamedCurves().contains(NamedCurve.SECP192R1));
        assertTrue("SECP256R1 should get parsed correctly", delegate.getNamedCurves().contains(NamedCurve.SECP256R1));
    }

    @Test(expected = ParameterException.class)
    public void testInvalidCurves() {
        args = new String[2];
        args[0] = "-named_curve";
        args[1] = "NOTACURVE"; // Not a correct
        // Curve
        jcommander.parse(args);
    }

    /**
     * Test of setNamedCurves method, of class EllipticCurveDelegate.
     */
    @Test
    public void testSetNamedCurves() {
        LinkedList<NamedCurve> supportedNamedCurves = new LinkedList<>();
        supportedNamedCurves.add(NamedCurve.BRAINPOOLP384R1);
        delegate.setNamedCurves(supportedNamedCurves);
        assertTrue("NamedCurves setter is not working correctly", delegate.getNamedCurves()
                .equals(supportedNamedCurves));
    }

    /**
     * Test of applyDelegate method, of class EllipticCurveDelegate.
     */
    @Test
    public void testApplyDelegate() {
        args = new String[4];
        args[0] = "-named_curve";
        args[1] = "SECP192R1,SECP256R1";
        args[2] = "-point_formats";
        args[3] = "ANSIX962_COMPRESSED_PRIME,UNCOMPRESSED";
        TlsConfig config = new TlsConfig();
        config.setNamedCurves(null);
        config.setPointFormats(null);
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue("SECP192R1 should get parsed correctly", config.getNamedCurves().contains(NamedCurve.SECP192R1));
        assertTrue("SECP256R1 should get parsed correctly", config.getNamedCurves().contains(NamedCurve.SECP192R1));
        assertTrue("UNCOMPRESSED should get parsed correctly",
                config.getPointFormats().contains(ECPointFormat.UNCOMPRESSED));
        assertTrue("ANSIX962_COMPRESSED_PRIME should get parsed correctly",
                config.getPointFormats().contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME));
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = new TlsConfig();
        TlsConfig config2 = new TlsConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }
}
