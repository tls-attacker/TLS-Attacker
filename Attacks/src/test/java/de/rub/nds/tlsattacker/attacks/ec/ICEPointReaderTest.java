package de.rub.nds.tlsattacker.attacks.ec;

import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ICEPointReaderTest {

    /**
     * Test of readPoints method, of class ICEPointReader.
     */
    @Test
    public void testReadPoints() throws Exception {
	String namedCurve = "secp192r1";
	List<ICEPoint> result = ICEPointReader.readPoints(namedCurve);

	assertEquals(5, result.get(0).getOrder());
    }

}
