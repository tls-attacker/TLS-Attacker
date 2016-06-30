/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.math.ec.ECPoint;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECCUtilsBCWrapper {

    private ECCUtilsBCWrapper() {

    }

    /**
     * Reads ECC domain parameters from an inputstream, based on given named
     * curves and point formats. It uses the BC functionality.
     * 
     * 
     * @param namedCurves
     * @param pointFormats
     * @param input
     * @return
     * @throws IOException
     */
    public static ECDomainParameters readECParameters(NamedCurve[] namedCurves, ECPointFormat[] pointFormats,
	    InputStream input) throws IOException {
	int[] nc = convertNamedCurves(namedCurves);
	short[] pf = convertPointFormats(pointFormats);
	return TlsECCUtils.readECParameters(nc, pf, input);
    }

    /**
     * Reads ECC domain parameters from an InputStream, all named formats and
     * point formats are allowed
     * 
     * @param input
     * @return
     * @throws IOException
     */
    public static ECDomainParameters readECParameters(InputStream input) throws IOException {
	NamedCurve[] namedCurves = NamedCurve.values();
	ECPointFormat[] poinFormats = ECPointFormat.values();
	return readECParameters(namedCurves, poinFormats, input);
    }

    /**
     * Reads ECC domain parameters from an InputStream, all named formats and
     * point formats are allowed. Then, it also reads the public key provided in
     * the input stream.
     * 
     * @param input
     * @return
     * @throws IOException
     */
    public static ECPublicKeyParameters readECParametersWithPublicKey(InputStream input) throws IOException {
	ECDomainParameters domainParameters = readECParameters(input);

	// read the length byte for the ec point
	int length = input.read();
	byte[] point = new byte[length];
	// read the point bytes
	input.read(point);

	short[] pointFormats = convertPointFormats(ECPointFormat.values());
        return TlsECCUtils.deserializeECPublicKey(pointFormats, domainParameters, point);
    }
    private static final Logger LOG = Logger.getLogger(ECCUtilsBCWrapper.class.getName());

    /**
     * Converts named curves into BC style notation
     * 
     * @param namedCurves
     * @return
     */
    public static int[] convertNamedCurves(NamedCurve[] namedCurves) {
	if (namedCurves == null || namedCurves.length == 0) {
	    return null;
	}
	int[] nc = new int[namedCurves.length];
	for (int i = 0; i < namedCurves.length; i++) {
	    nc[i] = namedCurves[i].getIntValue();
	}
	return nc;
    }

    /**
     * Converts point formats into BC style notation
     * 
     * @param pointFormats
     * @return
     */
    public static short[] convertPointFormats(ECPointFormat[] pointFormats) {
	if (pointFormats == null || pointFormats.length == 0) {
	    return null;
	}
	short[] pf = new short[pointFormats.length];
	for (int i = 0; i < pointFormats.length; i++) {
	    pf[i] = pointFormats[i].getShortValue();
	}
	return pf;
    }

    /**
     * Serializes an ec point and returns its encoded version, consisting of one
     * byte encoding information and ec coordinates
     * 
     * @param ecPointFormats
     * @param point
     * @return
     * @throws IOException
     */
    public static byte[] serializeECPoint(ECPointFormat[] ecPointFormats, ECPoint point) throws IOException {
	short[] pf = convertPointFormats(ecPointFormats);
	return TlsECCUtils.serializeECPoint(pf, point);
    }
}
