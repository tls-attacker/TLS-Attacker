/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.handler.extension.EllipticCurvesExtensionHandler;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EllipticCurvesExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EllipticCurvesExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class EllipticCurvesExtensionHandlerTest {

    private EllipticCurvesExtensionHandler handler;
    private TlsContext context;

    public EllipticCurvesExtensionHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new EllipticCurvesExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class EllipticCurvesExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        EllipticCurvesExtensionMessage msg = new EllipticCurvesExtensionMessage();
        msg.setSupportedCurves(new byte[] { 0, 1, 0, 2 });
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientNamedCurvesList().size() == 2);
        assertTrue(context.getClientNamedCurvesList().get(0) == NamedCurve.SECT163K1);
        assertTrue(context.getClientNamedCurvesList().get(1) == NamedCurve.SECT163R1);
    }

    @Test
    public void testAdjustTLSContextUnknownCurve() {
        EllipticCurvesExtensionMessage msg = new EllipticCurvesExtensionMessage();
        msg.setSupportedCurves(new byte[] { (byte) 0xFF, (byte) 0xEE });
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientNamedCurvesList().isEmpty());
    }

    /**
     * Test of getParser method, of class EllipticCurvesExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 1, 2 }, 0) instanceof EllipticCurvesExtensionParser);
    }

    /**
     * Test of getPreparator method, of class EllipticCurvesExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new EllipticCurvesExtensionMessage()) instanceof EllipticCurvesExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class EllipticCurvesExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new EllipticCurvesExtensionMessage()) instanceof EllipticCurvesExtensionSerializer);
    }

}
