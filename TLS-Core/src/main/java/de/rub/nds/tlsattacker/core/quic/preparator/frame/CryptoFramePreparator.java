/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CryptoFramePreparator extends QuicFramePreparator<CryptoFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CryptoFramePreparator(Chooser chooser, CryptoFrame frame) {
        super(chooser, frame);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing CRYPTO Frame");
        prepareCryptoData(getObject());
        prepareLengthData(getObject());
        prepareOffsetData(getObject());
    }

    protected void prepareCryptoData(CryptoFrame frame) {
        frame.setCryptoData(frame.getCryptoDataConfig());
        LOGGER.debug("Crypto Data: {}", frame.getCryptoData().getValue());
    }

    protected void prepareLengthData(CryptoFrame frame) {
        frame.setLength(frame.getLengthConfig());
        LOGGER.debug("Length: {}", frame.getLength().getValue());
    }

    protected void prepareOffsetData(CryptoFrame frame) {
        frame.setOffset(frame.getOffsetConfig());
        LOGGER.debug("Offset: {}", frame.getOffset().getValue());
    }
}
