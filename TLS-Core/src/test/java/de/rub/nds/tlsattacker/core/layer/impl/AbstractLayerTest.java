/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;

public abstract class AbstractLayerTest {

    protected Config config;

    protected Context context;

    protected TlsContext tlsContext;

    protected FakeTransportHandler transportHandler;

    protected State state;

    private static final Logger LOGGER = LogManager.getLogger();

    public void setUpLayerSpecific() {}

    public void applyDelegate() {}

    @BeforeEach
    public void setUp() throws IOException {
        config = new Config();
        applyDelegate();
        state = new State(config);
        context = state.getContext();
        tlsContext = context.getTlsContext();
        FakeTcpTransportHandler fakeTcpTransportHandler = new FakeTcpTransportHandler(null);
        transportHandler = fakeTcpTransportHandler;
        tlsContext.setTransportHandler(fakeTcpTransportHandler);
        ProviderUtil.addBouncyCastleProvider();
        setUpLayerSpecific();
    }
}
