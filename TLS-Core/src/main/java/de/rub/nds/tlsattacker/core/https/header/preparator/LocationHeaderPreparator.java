/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https.header.preparator;

import de.rub.nds.tlsattacker.core.https.header.LocationHeader;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LocationHeaderPreparator extends Preparator<LocationHeader> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final LocationHeader header;

    public LocationHeaderPreparator(Chooser chooser, LocationHeader header) {
        super(chooser, header);
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Location");
        // if we do not find a request path in the context, none was set or interpreted during the connection, we
        // then use a default value
        String lastRequestPath = chooser.getContext().getHttpContext().getLastRequestPath();
        if (lastRequestPath != null) {
            header.setHeaderValue(lastRequestPath);
        } else {
            LOGGER.debug("Request path was not set or interpreted during the connection, we use default value from the"
                + " config instead");
            header.setHeaderValue(chooser.getConfig().getDefaultHttpsLocationPath());
        }
    }
}
