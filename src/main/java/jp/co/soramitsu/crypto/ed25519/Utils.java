/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 */
package jp.co.soramitsu.crypto.ed25519;

/**
 * Basic utilities for EdDSA.
 * Not for external use, not maintained as a public API.
 *
 * @author str4d
 *
 */
public class Utils {

  /**
   * Constant-time byte comparison.
   * @param b a byte
   * @param c a byte
   * @return 1 if b and c are equal, 0 otherwise.
   */
  public static int equal(int b, int c) {
    int result = 0;
    int xor = b ^ c;
    for (int i = 0; i < 8; i++) {
      result |= xor >> i;
    }
    return (result ^ 0x01) & 0x01;
  }

  /**
   * Constant-time byte[] comparison.
   * @param b a byte[]
   * @param c a byte[]
   * @return 1 if b and c are equal, 0 otherwise.
   */
  public static int equal(byte[] b, byte[] c) {
    int result = 0;
    for (int i = 0; i < 32; i++) {
      result |= b[i] ^ c[i];
    }

    return equal(result, 0);
  }

  /**
   * Constant-time determine if byte is negative.
   * @param b the byte to check.
   * @return 1 if the byte is negative, 0 otherwise.
   */
  public static int negative(int b) {
    return (b >> 8) & 1;
  }

  /**
   * Get the i'th bit of a byte array.
   * @param h the byte array.
   * @param i the bit index.
   * @return 0 or 1, the value of the i'th bit in h
   */
  public static int bit(byte[] h, int i) {
    return (h[i >> 3] >> (i & 7)) & 1;
  }
}
