package tlsattacker.fuzzer.config.mutator;

import java.io.Serializable;
import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A Config File which controls the SimpleMutator.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class SimpleMutatorConfig implements Serializable {

    /**
     * Percentage with which a random variable should be modified
     */
    private Integer modifyVariablePercentage = 50;

    /**
     * Percentage with which a record should be added
     */
    private Integer addRecordPercentage = 50;

    /**
     * Percentage with which a message should be added to a SendAction
     */
    private Integer addMessagePercentage = 20;

    /**
     * Percentage with which a message should be removed from a SendAction
     */
    private Integer removeMessagePercentage = 1;

    /**
     * Percentage with which the server certificate should be changed
     */
    private Integer changeServerCertPercentage = 2;

    /**
     * Percentage with which the client certificate should be changed
     */
    private Integer changeClientCertPercentage = 2;

    /**
     * Percentage with which a random message should be duplicated
     */
    private Integer duplicateMessagePercentage = 1;

    /**
     * Percentage with which multiple modifications should be applied to
     * TestVector
     */
    private Integer multipleModifications = 1;

    /**
     * Percentage with which a new SendReceive Action pair should be added to a
     * TestVector
     */
    private Integer addFlightPercentage = 50;

    /**
     * Percentage with which a new ToggleEncryptionAction should be added to the
     * TestVector
     */
    private Integer addToggleEncrytionPercentage = 2;

    /**
     * Percentage with which a new context changing action should be added to
     * the TestVector
     */
    private Integer addContextActionPercentage = 4;

    /**
     * Percentage with which an extension is added to Hello message
     */
    private Integer addExtensionMessagePercentage = 20;

    public SimpleMutatorConfig() {
    }

    public Integer getAddExtensionPercentage() {
        return addExtensionMessagePercentage;
    }

    public void setAddExtensionMessagePercentage(Integer addExtensionMessagePercentage) {
        this.addExtensionMessagePercentage = addExtensionMessagePercentage;
    }

    public Integer getAddContextActionPercentage() {
        return addContextActionPercentage;
    }

    public void setAddContextActionPercentage(Integer addContextActionPercentage) {
        this.addContextActionPercentage = addContextActionPercentage;
    }

    public Integer getAddToggleEncrytionPercentage() {
        return addToggleEncrytionPercentage;
    }

    public void setAddToggleEncrytionPercentage(Integer addToggleEncrytionPercentage) {
        this.addToggleEncrytionPercentage = addToggleEncrytionPercentage;
    }

    public Integer getAddFlightPercentage() {
        return addFlightPercentage;
    }

    public void setAddFlightPercentage(Integer addFlightPercentage) {
        this.addFlightPercentage = addFlightPercentage;
    }

    public Integer getMultipleModifications() {
        return multipleModifications;
    }

    public void setMultipleModifications(Integer multipleModifications) {
        this.multipleModifications = multipleModifications;
    }

    public Integer getChangeServerCert() {
        return changeServerCertPercentage;
    }

    public void setChangeServerCert(Integer changeServerCert) {
        this.changeServerCertPercentage = changeServerCert;
    }

    public Integer getChangeClientCertPercentage() {
        return changeClientCertPercentage;
    }

    public void setChangeClientCertPercentage(Integer changeClientCertPercentage) {
        this.changeClientCertPercentage = changeClientCertPercentage;
    }

    public Integer getDuplicateMessagePercentage() {
        return duplicateMessagePercentage;
    }

    public void setDuplicateMessagePercentage(Integer duplicateMessagePercentage) {
        this.duplicateMessagePercentage = duplicateMessagePercentage;
    }

    public Integer getRemoveMessagePercentage() {
        return removeMessagePercentage;
    }

    public void setRemoveMessagePercentage(Integer removeMessagePercentage) {
        this.removeMessagePercentage = removeMessagePercentage;
        if (removeMessagePercentage > 100) {
            throw new IllegalArgumentException("RemoveMessagePercentage cannot be >100:" + removeMessagePercentage);
        }
    }

    public Integer getModifyVariablePercentage() {
        return modifyVariablePercentage;
    }

    public void setModifyVariablePercentage(Integer modifyVariablePercentage) {
        this.modifyVariablePercentage = modifyVariablePercentage;
        if (modifyVariablePercentage > 100) {
            throw new IllegalArgumentException("ModifyVariablePercentage cannot be >100:" + modifyVariablePercentage);
        }
    }

    public Integer getAddRecordPercentage() {
        return addRecordPercentage;

    }

    public void setAddRecordPercentage(Integer addRecordPercentage) {
        this.addRecordPercentage = addRecordPercentage;
        if (addRecordPercentage > 100) {
            throw new IllegalArgumentException("AddRecordPercentage cannot be >100:" + addRecordPercentage);
        }
    }

    public Integer getAddMessagePercentage() {
        return addMessagePercentage;
    }

    public void setAddMessagePercentage(Integer addMessagePercentage) {
        this.addMessagePercentage = addMessagePercentage;
        if (addMessagePercentage > 100) {
            throw new IllegalArgumentException("AddMessagePercentage cannot be >100:" + addMessagePercentage);
        }
    }

    private static final Logger LOG = Logger.getLogger(SimpleMutatorConfig.class.getName());
}
