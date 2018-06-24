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
package jp.co.soramitsu.crypto.ed25519.math;

import javax.xml.bind.DatatypeConverter;

final class Constants {

  public static final byte[] ZERO = DatatypeConverter
      .parseHexBinary("0000000000000000000000000000000000000000000000000000000000000000");
  public static final byte[] ONE = DatatypeConverter
      .parseHexBinary("0100000000000000000000000000000000000000000000000000000000000000");
  public static final byte[] TWO = DatatypeConverter
      .parseHexBinary("0200000000000000000000000000000000000000000000000000000000000000");
  public static final byte[] FOUR = DatatypeConverter
      .parseHexBinary("0400000000000000000000000000000000000000000000000000000000000000");
  public static final byte[] FIVE = DatatypeConverter
      .parseHexBinary("0500000000000000000000000000000000000000000000000000000000000000");
  public static final byte[] EIGHT = DatatypeConverter
      .parseHexBinary("0800000000000000000000000000000000000000000000000000000000000000");
}
