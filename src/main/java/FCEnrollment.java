import org.hyperledger.fabric.sdk.Enrollment;

import java.security.PrivateKey;

public class FCEnrollment implements Enrollment {
    private PrivateKey privateKey;
    private String certificate;

    public FCEnrollment(PrivateKey privateKey, String certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    @Override
    public PrivateKey getKey() {
        return privateKey;
    }

    @Override
    public String getCert() {
        return certificate;
    }
}
