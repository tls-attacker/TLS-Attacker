/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http.header.preparator;

import de.rub.nds.tlsattacker.core.http.header.LocationHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LocationHeaderPreparator extends Preparator<LocationHeader> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final LocationHeader header;

    private final HttpContext httpContext;

    public LocationHeaderPreparator(HttpContext httpContext, LocationHeader header) {
        super(httpContext.getChooser(), header);
        this.httpContext = httpContext;
        this.header = header;
    }

    @Override
    public void prepare() {
        header.setHeaderName("Location");
        // if we do not find a request path in the context, none was set or interpreted during the
        // connection, we
        // then use a default value
        String lastRequestPath = httpContext.getLastRequestPath();
        if (lastRequestPath != null) {
            header.setHeaderValue(lastRequestPath);
        } else {
            LOGGER.debug(
                    "Request path was not set or interpreted during the connection, we use default value from the"
                            + " config instead");
            header.setHeaderValue(chooser.getConfig().getDefaultHttpsLocationPath());
        }
    }
}
