/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.math.ec.ECPoint;

public class ECCUtilsBCWrapper {

    /**
     * Reads ECC domain parameters from an inputstream, based on given named
     * curves and point formats. It uses the BC functionality.
     *
     * @param namedCurves
     *            The Array of namedCurves
     * @param pointFormats
     *            The Array of ECPointFormats
     * @param input
     *            The Inputstream to read from
     * @return ECDomainParameters
     * @throws IOException
     *             If something goes wrong while reading from the Stream
     */
    public static ECDomainParameters readECParameters(NamedGroup[] namedCurves, ECPointFormat[] pointFormats,
            InputStream input) throws IOException {
        int[] nc = convertNamedCurves(namedCurves);
        short[] pf = convertPointFormats(pointFormats);
        return TlsECCUtils.readECParameters(nc, pf, input);
    }

    public static ECDomainParameters readECParameters(NamedGroup namedGroup, ECPointFormat pointFormat,
            InputStream input) throws IOException {
        int[] nc = convertNamedCurves(new NamedGroup[] { namedGroup });
        short[] pf = convertPointFormats(new ECPointFormat[] { pointFormat });
        return TlsECCUtils.readECParameters(nc, pf, input);
    }

    /**
     * Reads ECC domain parameters from an InputStream, all named formats and
     * point formats are allowed
     *
     * @param input
     *            The Inputstream to read from
     * @return ECDomainParameters
     * @throws IOException
     *             If something goes wrong while reading from the Stream
     */
    public static ECDomainParameters readECParameters(InputStream input) throws IOException {
        NamedGroup[] namedCurves = NamedGroup.values();
        ECPointFormat[] poinFormats = ECPointFormat.values();
        return readECParameters(namedCurves, poinFormats, input);
    }

    /**
     * Reads ECC domain parameters from an InputStream, all named formats and
     * point formats are allowed. Then, it also reads the public key provided in
     * the input stream.
     *
     * @param input
     *            The InputStream to read from
     * @return ECPublicKeyParameters
     * @throws IOException
     *             If something goes wrong while reading from the Stream
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

    /**
     * Converts named curves into BC style notation
     *
     * @param namedCurves
     *            The NamedCurves to convert
     * @return int[] of the NamedCurves in BC Style
     */
    public static int[] convertNamedCurves(NamedGroup[] namedCurves) {
        if (namedCurves == null || namedCurves.length == 0) {
            return new int[0];
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
     *            The pointFormats to convert
     * @return The converted PointFormats
     */
    public static short[] convertPointFormats(ECPointFormat[] pointFormats) {
        if (pointFormats == null || pointFormats.length == 0) {
            return new short[0];
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
     *            The EcPointFormats
     * @param point
     *            The Point that should be converted
     * @return The serialized ECPoint
     * @throws IOException
     *             If something goes wrong during Serialisation
     */
    public static byte[] serializeECPoint(ECPointFormat[] ecPointFormats, ECPoint point) throws IOException {
        short[] pf = convertPointFormats(ecPointFormats);
        return TlsECCUtils.serializeECPoint(pf, point);
    }

    public static byte[] serializeEcFieldElement(int fieldSize, BigInteger element) throws IOException {
        return TlsECCUtils.serializeECFieldElement(fieldSize, element);
    }

    private ECCUtilsBCWrapper() {

    }
}
