/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownHandshakeMessageSerializer;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FragmentedMessage {

    protected static final Logger LOGGER = LogManager.getLogger(FragmentedMessage.class.getName());

    private final int size;

    private Byte type;

    private final Byte[] byteBuffer;

    private final List<DtlsHandshakeMessageFragment> fragmentData;

    public FragmentedMessage(int size) {
        this.size = size;
        byteBuffer = new Byte[2 << 25];
        fragmentData = new LinkedList<>();
    }

    public void insertFragment(DtlsHandshakeMessageFragment fragment) {
        if (type == null) {
            type = fragment.getType().getValue();
        } else {
            if (type != fragment.getType().getValue()) {
                LOGGER.warn("Found an unffiting fragment! Type before:" + type + " inserted type:" + fragment.getType().getValue());
            }
        }
        fragmentData.add(fragment);
        ArrayUtils.insert(fragment.getFragmentOffset().getValue(), byteBuffer, fragment.getContent());
    }

    public byte[] getReconstructedMessageStream() {
        if (!isMessageComplete()) {
            LOGGER.warn("Returning incompletly received message! Missing pieces are replaced by 0.");
        }
        if (type == null) {
            throw new WorkflowExecutionException("DtlsFragmentedMessage does not have type!");
        }
        Byte[] reconstructedContent = new Byte[size];
        System.arraycopy(byteBuffer, 0, reconstructedContent, 0, size);
        UnknownHandshakeMessage message = new UnknownHandshakeMessage();
        message.setType(type);
        message.setLength(reconstructedContent.length);
        message.setDataConfig(ArrayUtils.toPrimitive(byteBuffer, (byte) 0));
        UnknownHandshakeMessageSerializer serializer = new UnknownHandshakeMessageSerializer(message, null);
        return serializer.serialize();
    }

    public boolean isMessageComplete() {
        for (int i = 0; i < size; i++) {
            if (byteBuffer[i] == null) {
                return false;
            }
        }
        return true;
    }

}
