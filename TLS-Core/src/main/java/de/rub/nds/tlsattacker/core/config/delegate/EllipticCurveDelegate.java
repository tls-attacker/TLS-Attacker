/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.NamedCurveConverter;
import de.rub.nds.tlsattacker.core.config.converters.PointFormatConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import java.util.Collections;
import java.util.List;

public class EllipticCurveDelegate extends Delegate {

    @Parameter(names = "-point_formats", description = "Sets the elliptic curve point formats, divided by a comma", converter = PointFormatConverter.class)
    private List<ECPointFormat> pointFormats = null;
    @Parameter(names = "-named_curve", description = "Named curves to be used, divided by a comma", converter = NamedCurveConverter.class)
    private List<NamedCurve> namedCurves = null;

    public EllipticCurveDelegate() {
    }

    public List<ECPointFormat> getPointFormats() {
        if (pointFormats == null) {
            return null;
        }
        return Collections.unmodifiableList(pointFormats);
    }

    public void setPointFormats(List<ECPointFormat> pointFormats) {
        this.pointFormats = pointFormats;
    }

    public List<NamedCurve> getNamedCurves() {
        if (namedCurves == null) {
            return null;
        }
        return Collections.unmodifiableList(namedCurves);
    }

    public void setNamedCurves(List<NamedCurve> namedCurves) {
        this.namedCurves = namedCurves;
    }

    @Override
    public void applyDelegate(Config config) {
        if (namedCurves != null) {
            config.setNamedCurves(namedCurves);
        }
        if (pointFormats != null) {
            config.setDefaultServerSupportedPointFormats(pointFormats);
            config.setDefaultClientSupportedPointFormats(pointFormats);
        }
    }
}
