package de.rub.nds.tlsattacker.core.workflow.action.executor;

/**
 * DTLS message information contains DTLS-relevant information associated with
 * each message. For non-handshake messages, messageSequence should be null.
 */
public class DtlsMessageInformation {
    private Integer epoch;
    private Integer messageSequence;

    public DtlsMessageInformation(Integer epoch) {
        this.epoch = epoch;
    }

    public DtlsMessageInformation(Integer epoch, Integer messageSequence) {
        this.epoch = epoch;
        this.messageSequence = messageSequence;
    }

    public Integer getEpoch() {
        return epoch;
    }

    public void setEpoch(Integer epoch) {
        this.epoch = epoch;
    }

    public Integer getMessageSequence() {
        return messageSequence;
    }

    public void setMessageSequence(Integer messageSequence) {
        this.messageSequence = messageSequence;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("{epoch=").append(epoch);
        builder.append(", message_seq=").append(messageSequence);
        return builder.append("}").toString();
    }
}
