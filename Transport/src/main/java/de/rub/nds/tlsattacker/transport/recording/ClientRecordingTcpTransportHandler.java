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
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.io.IOException;

public class ClientRecordingTcpTransportHandler extends ClientTcpTransportHandler {

    private final Recording recording;

    public ClientRecordingTcpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, hostname, port);
        RandomHelper.getRandom().setSeed(0);
        recording = new Recording(0);
    }

    @Override
    public void initialize() throws IOException {
        super.initialize();
    }

    @Override
    public void sendData(byte[] data) throws IOException {

        super.sendData(data);
        recording.addSentLine(new RecordedLine(data));
    }

    @Override
    public byte[] fetchData() throws IOException {
        byte[] data = super.fetchData();
        recording.addReceivedLine(new RecordedLine(data));
        return data;
    }

    public Recording getRecording() {
        return recording;
    }
}
