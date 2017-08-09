import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;

/**
 * Created by shomakhov on 08.08.2017.
 */
public class RegisterUser {
    public static FCUser registerUser(String userName, FCUser admin, HFCAClient client, String MspId) throws Exception {
        FCUser org1_user = new FCUser(userName);
        RegistrationRequest registrationRequest = new RegistrationRequest(org1_user.getName(), "org1.department1");
        String enrollmentSecret = client.register(registrationRequest, admin);

        org1_user.setEnrollment(client.enroll(org1_user.getName(), enrollmentSecret));
        org1_user.setMspId(MspId);
        return org1_user;
    }
}
