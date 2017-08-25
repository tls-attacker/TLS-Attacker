/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.recording;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PlayBackTransportHandler extends TransportHandler {

    private final List<RecordedLine> linesToSend;

    private int position = 0;

    private final Recording recording;

    PlayBackTransportHandler(Recording recording) {
        super(0, ConnectionEndType.SERVER);
        this.recording = recording;
        linesToSend = recording.getReceivedLines();
    }

    @Override
    public void closeConnection() throws IOException {
    }

    @Override
    public void initialize() throws IOException {
        RandomHelper.getRandom().setSeed(recording.getSeed());
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        LOGGER.debug("Not sending Data. This is a recording");
    }

    @Override
    public byte[] fetchData() throws IOException {
        if (linesToSend.size() <= position) {
            LOGGER.warn("Recoding ended");
            return new byte[0];
        }
        RecordedLine data = linesToSend.get(position);
        position++;
        return data.getRecordedMessage();
    }
}
