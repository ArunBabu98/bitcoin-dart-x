import 'package:bitcoin_dart_x/crypto/ellipic/base.dart';

/// [PublicKey] represents a public key which is a point on a 2d [Curve],
///  taking [BigInt] X, Y as the coordinates on axis
class PublicKey extends AffinePoint {
  Curve curve;

  PublicKey(this.curve, BigInt X, BigInt Y) : super.fromXY(X, Y);

  PublicKey.fromPoint(this.curve, AffinePoint p) : super.fromXY(p.X, p.Y);

  PublicKey.fromHex(this.curve, String hex) {
    if (hex.length <= 2) {
      throw Exception("publickey hex length is invalid");
    }
    late PublicKey pub;
    var prefix = hex.substring(0, 2);
    switch (prefix) {
      case '02':
        pub = curve.compressedHexToPublicKey(hex);
        break;
      case '03':
        pub = curve.compressedHexToPublicKey(hex);
        break;
      case '04':
        pub = curve.hexToPublicKey(hex);
        break;
      default:
        throw Exception("Invalid Hex Key prefix!");
    }

    X = pub.X;
    Y = pub.Y;
  }

  /// [toHex] generate a compressed hex string from a public key
  String toHex() {
    return curve.publicKeyToHex(this);
  }

  /// [toCompressedHex] generate a compressed hex string from a public key
  String toCompressedHex() {
    return curve.publicKeyToCompressedHex(this);
  }

  /// [toString] equals to [toHex]
  @override
  String toString() {
    return toHex();
  }

  @override
  bool operator ==(other) {
    return other is PublicKey &&
        (curve == other.curve && X == other.X && Y == other.Y);
  }
}
