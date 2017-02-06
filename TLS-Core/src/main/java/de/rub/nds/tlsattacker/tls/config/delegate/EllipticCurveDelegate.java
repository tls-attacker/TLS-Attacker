/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.converters.NamedCurveConverter;
import de.rub.nds.tlsattacker.tls.config.converters.PointFormatConverter;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class EllipticCurveDelegate extends Delegate {
    //TODO Add example in description
    @Parameter(names = "-point_formats", description = "Sets the elliptic curve point formats", converter = PointFormatConverter.class)
    private List<ECPointFormat> pointFormats;
    //TODO Add example in description
    @Parameter(names = "-named_curve", description = "Named curves to be used, divided by a comma. ", converter = NamedCurveConverter.class)
    private List<NamedCurve> namedCurves;

    public EllipticCurveDelegate() {
        pointFormats = new LinkedList<>();
        pointFormats.add(ECPointFormat.UNCOMPRESSED);
        namedCurves = new LinkedList<>();
        namedCurves.add(NamedCurve.SECP192R1);
        namedCurves.add(NamedCurve.SECP256R1);
        namedCurves.add(NamedCurve.SECP384R1);
        namedCurves.add(NamedCurve.SECP521R1);
    }

    public List<ECPointFormat> getPointFormats() {
        return pointFormats;
    }

    public void setPointFormats(List<ECPointFormat> pointFormats) {
        this.pointFormats = pointFormats;
    }

    public List<NamedCurve> getNamedCurves() {
        return namedCurves;
    }

    public void setNamedCurves(List<NamedCurve> namedCurves) {
        this.namedCurves = namedCurves;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        config.setNamedCurves(namedCurves);
        config.setPointFormats(pointFormats);
    }
}
