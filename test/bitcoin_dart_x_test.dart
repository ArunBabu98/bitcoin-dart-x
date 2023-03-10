import 'package:bitcoin_dart_x/bip39/bip39.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bitcoin_dart_x/bitcoin_dart_x.dart';
import 'package:hex/hex.dart';

void main() {
  test('BIP39 check', () {
    BIP39 bip39 = BIP39();
    var temp = bip39.validateMnemonic(
        "hope manage police crys=tal card shy correct cabbage all assist sail universe keen chimney industry hire flat royal switch inmate grain genuine anchor later");
    print(temp);
  });
}
