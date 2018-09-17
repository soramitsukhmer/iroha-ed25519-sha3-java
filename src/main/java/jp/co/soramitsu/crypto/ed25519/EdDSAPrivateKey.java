package jp.co.soramitsu.crypto.ed25519;

import java.security.PrivateKey;
import java.util.Arrays;
import jp.co.soramitsu.crypto.ed25519.math.GroupElement;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec;

/**
 * An EdDSA private key.
 */
public class EdDSAPrivateKey implements EdDSAKey, PrivateKey {

  private static final long serialVersionUID = 23495873459878957L;
  private final byte[] seed;
  private final byte[] h;
  private final byte[] a;
  private final GroupElement A;
  private final byte[] Abyte;
  private final EdDSAParameterSpec edDsaSpec;

  public EdDSAPrivateKey(EdDSAPrivateKeySpec spec) {
    this.seed = spec.getSeed();
    this.h = spec.getH();
    this.a = spec.geta();
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

  /**
   * Returns the public key in its canonical encoding.
   */
  @Override
  public byte[] getEncoded() {
    if (seed == null) {
      return null;
    }
    return seed;
  }


  @Override
  public EdDSAParameterSpec getParams() {
    return edDsaSpec;
  }

  /**
   * @return will be null if constructed from a spec which was directly constructed from H
   */
  public byte[] getSeed() {
    return seed;
  }

  /**
   * @return the hash of the seed
   */
  public byte[] getH() {
    return h;
  }

  /**
   * @return the private key
   */
  public byte[] geta() {
    return a;
  }

  /**
   * @return the public key
   */
  public GroupElement getA() {
    return A;
  }

  /**
   * @return the public key
   */
  public byte[] getAbyte() {
    return Abyte;
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(seed);
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (!(o instanceof EdDSAPrivateKey)) {
      return false;
    }
    EdDSAPrivateKey pk = (EdDSAPrivateKey) o;
    return Arrays.equals(seed, pk.getSeed()) &&
        edDsaSpec.equals(pk.getParams());
  }
}
