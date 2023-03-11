import 'package:bitcoin_dart_x/crypto/ecdsa.dart';
import 'package:bitcoin_dart_x/crypto/ellipic/curves.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('ECDSA - secp256k1 test', () {
    var ec = getSecp256k1();
    var priv = ec.generatePrivateKey();
    var pub = priv.publicKey;
    print(priv);
    print(pub);
    var hashHex =
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
    var hash = List<int>.generate(hashHex.length ~/ 2,
        (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));
    var sig = ECDSA().signature(priv, hash);

    var result = ECDSA().verify(pub, hash, sig);
    expect(result, true, reason: "Not valid ECDSA!");
  });
}
