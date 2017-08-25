/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.recording;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ClientRecordingTcpTransportHandler extends ClientTcpTransportHandler {

    private List<byte[]> sendDataCallList;
    private List<byte[]> fetchDataCallList;

    private int fetchPlayBack = 0;

    private boolean playBack = false;

    public ClientRecordingTcpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, hostname, port);
        sendDataCallList = new LinkedList<>();
        fetchDataCallList = new LinkedList<>();
        playBack = false;
    }

    public ClientRecordingTcpTransportHandler(List<byte[]> sendData, List<byte[]> receiveData) {
        super(0, null, 0);
        this.sendDataCallList = sendData;
        this.fetchDataCallList = receiveData;
        playBack = true;
    }

    @Override
    public void initialize() throws IOException {
        if (!playBack) {
            super.initialize();
        }
    }

    @Override
    public void sendData(byte[] data) throws IOException {
        if (!playBack) {
            super.sendData(data);
            sendDataCallList.add(data);
            LOGGER.info("Sending Data:" + ArrayConverter.bytesToHexString(data));
        } else {
            LOGGER.debug("Not sending Data. This is a recording");
        }
    }

    @Override
    public byte[] fetchData() throws IOException {
        if (!playBack) {
            byte[] data = super.fetchData();
            fetchDataCallList.add(data);
            LOGGER.info("Fetch Data:" + ArrayConverter.bytesToHexString(data));
            return data;
        } else {
            if (fetchDataCallList.size() <= fetchPlayBack) {
                LOGGER.warn("Recoding ended");
                return null;
            }
            byte[] data = fetchDataCallList.get(fetchPlayBack);
            fetchPlayBack++;
            return data;
        }
    }

    public List<byte[]> getSendDataCallList() {
        return sendDataCallList;
    }

    public void setSendDataCallList(List<byte[]> sendDataCallList) {
        this.sendDataCallList = sendDataCallList;
    }

    public List<byte[]> getFetchDataCallList() {
        return fetchDataCallList;
    }

    public void setFetchDataCallList(List<byte[]> fetchDataCallList) {
        this.fetchDataCallList = fetchDataCallList;
    }
}
