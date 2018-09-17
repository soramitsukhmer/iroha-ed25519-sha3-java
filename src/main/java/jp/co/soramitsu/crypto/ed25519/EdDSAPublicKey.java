package jp.co.soramitsu.crypto.ed25519;

import java.security.PublicKey;
import java.util.Arrays;
import jp.co.soramitsu.crypto.ed25519.math.GroupElement;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec;

/**
 * An EdDSA public key.
 * <p>
 * Warning: Public key encoding is is based on the current curdle WG draft, and is subject to
 * change. See getEncoded().
 * </p><p>
 * For compatibility with older releases, decoding supports both the old and new draft
 * specifications. See decode().
 * </p><p>
 * Ref: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
 * </p><p>
 * Old Ref: https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
 * </p>
 *
 * @author str4d
 */
public class EdDSAPublicKey implements EdDSAKey, PublicKey {

  private static final long serialVersionUID = 9837459837498475L;
  private final GroupElement A;
  private final byte[] Abyte;
  private final EdDSAParameterSpec edDsaSpec;
  private GroupElement Aneg = null;

  public EdDSAPublicKey(EdDSAPublicKeySpec spec) {
    this.A = spec.getA();
    this.Abyte = this.A.toByteArray();
    this.edDsaSpec = spec.getParams();
  }

  @Override
  public String getAlgorithm() {
    return KEY_ALGORITHM;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    return this.Abyte;
  }

  @Override
  public EdDSAParameterSpec getParams() {
    return edDsaSpec;
  }

  public GroupElement getA() {
    return A;
  }

  public GroupElement getNegativeA() {
    // Only read Aneg once, otherwise read re-ordering might occur between here and return. Requires all GroupElement's fields to be final.
    GroupElement ourAneg = Aneg;
    if (ourAneg == null) {
      ourAneg = A.negate();
      Aneg = ourAneg;
    }
    return ourAneg;
  }

  public byte[] getAbyte() {
    return Abyte;
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(Abyte);
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (!(o instanceof EdDSAPublicKey)) {
      return false;
    }
    EdDSAPublicKey pk = (EdDSAPublicKey) o;
    return Arrays.equals(Abyte, pk.getAbyte()) &&
        edDsaSpec.equals(pk.getParams());
  }
}
