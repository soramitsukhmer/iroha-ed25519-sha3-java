package jp.co.soramitsu.crypto.ed25519;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class EdDSASecurityProviderTest {

  @Rule
  public ExpectedException exception = ExpectedException.none();

  @Test
  public void canGetInstancesWhenProviderIsPresent() throws Exception {
    Security.addProvider(new EdDSASecurityProvider());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM, "EdDSA");
    KeyFactory keyFac = KeyFactory.getInstance(EdDSAKey.KEY_ALGORITHM, "EdDSA");
    Signature sgr = Signature.getInstance(EdDSAEngine.SIGNATURE_ALGORITHM, "EdDSA");

    Security.removeProvider("EdDSA");
  }

  @Test
  public void cannotGetInstancesWhenProviderIsNotPresent() throws Exception {
    exception.expect(NoSuchProviderException.class);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM, "EdDSA");
  }
}
