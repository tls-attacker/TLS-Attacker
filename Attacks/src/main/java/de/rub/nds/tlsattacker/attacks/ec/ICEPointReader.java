/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class ICEPointReader {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Reads points for the attack on elliptic curves from a file specific for
     * this named curve
     *
     * @param group
     *            The NamedCurve as a String
     * @return the deserialized Points
     */
    public static List<ICEPoint> readPoints(NamedGroup group) {
        EllipticCurve curve = CurveFactory.getCurve(group);
        String namedCurveLow = group.name().toLowerCase();
        String fileName = "points_" + namedCurveLow + ".txt";

        BufferedReader br = new BufferedReader(new InputStreamReader(ICEPointReader.class.getClassLoader()
                .getResourceAsStream(fileName)));
        String line;
        List<ICEPoint> points = new LinkedList<>();
        try {
            while ((line = br.readLine()) != null) {
                if (line.length() != 0 && !line.startsWith("#")) {
                    String[] nums = line.split("\\s+,\\s+");
                    int order = Integer.parseInt(nums[0]);
                    BigInteger x = new BigInteger(nums[1], 16);
                    BigInteger y = new BigInteger(nums[2], 16);
                    points.add(new ICEPoint(x, y, curve, order));
                }
            }
            Collections.sort(points, new ICEPointCopmparator());
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Using the following curves and points");
                for (ICEPoint p : points) {
                    LOGGER.debug(p.getOrder() + " , " + p.getX().getData().toString(16) + " , "
                            + p.getY().getData().toString(16));
                }
            }
            return points;
        } catch (IOException | NumberFormatException ex) {
            throw new ConfigurationException(ex.getLocalizedMessage(), ex);
        } finally {
            try {
                br.close();
            } catch (IOException ex) {
                LOGGER.error("Failed to close stream", ex);
            }
        }
    }

    private ICEPointReader() {

    }
}
