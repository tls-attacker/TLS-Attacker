package de.rub.nds.tlsattacker.core.dtls;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.DtlsMessageInformation;

public class MessageCache {

    private Set<MessageKey> keys = new HashSet<>();

    public MessageCache() {
    }

    public void addMessage(ProtocolMessage message, DtlsMessageInformation info) {
        keys.add(new MessageKey(message, info));
    }

    public boolean hasMessage(ProtocolMessage message, DtlsMessageInformation info) {
        return keys.contains(new MessageKey(message, info));
    }

    static class MessageKey {

        private byte[] messageBytes;
        private Integer messageSequence;
        private Integer epochNumber;

        public MessageKey(ProtocolMessage message, DtlsMessageInformation info) {
            messageBytes = message.getCompleteResultingMessage().getValue();
            messageSequence = info.getMessageSequence();
            epochNumber = info.getEpoch();
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((epochNumber == null) ? 0 : epochNumber.hashCode());
            result = prime * result + Arrays.hashCode(messageBytes);
            result = prime * result + ((messageSequence == null) ? 0 : messageSequence.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            MessageKey other = (MessageKey) obj;
            if (epochNumber == null) {
                if (other.epochNumber != null)
                    return false;
            } else if (!epochNumber.equals(other.epochNumber))
                return false;
            if (!Arrays.equals(messageBytes, other.messageBytes))
                return false;
            if (messageSequence == null) {
                if (other.messageSequence != null)
                    return false;
            } else if (!messageSequence.equals(other.messageSequence))
                return false;
            return true;
        }
    }
}
