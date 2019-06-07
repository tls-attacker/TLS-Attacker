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
import de.rub.nds.tlsattacker.core.config.converters.NamedGroupConverter;
import de.rub.nds.tlsattacker.core.config.converters.PointFormatConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.Collections;
import java.util.List;

public class NamedGroupsDelegate extends Delegate {

    @Parameter(names = "-point_formats", description = "Sets the elliptic curve point formats, divided by a comma", converter = PointFormatConverter.class)
    private List<ECPointFormat> pointFormats = null;
    @Parameter(names = "-named_group", description = "Named groups to be used, divided by a comma", converter = NamedGroupConverter.class)
    private List<NamedGroup> namedGroups = null;

    public NamedGroupsDelegate() {
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

    public List<NamedGroup> getNamedGroups() {
        if (namedGroups == null) {
            return null;
        }
        return Collections.unmodifiableList(namedGroups);
    }

    public void setNamedGroups(List<NamedGroup> namedGroups) {
        this.namedGroups = namedGroups;
    }

    @Override
    public void applyDelegate(Config config) {
        if (namedGroups != null) {
            config.setDefaultClientNamedGroups(namedGroups);
            config.setDefaultServerNamedGroups(namedGroups);
            config.setDefaultSelectedNamedGroup(namedGroups.get(0));
        }
        if (pointFormats != null) {
            config.setDefaultServerSupportedPointFormats(pointFormats);
            config.setDefaultClientSupportedPointFormats(pointFormats);
        }
    }
}
