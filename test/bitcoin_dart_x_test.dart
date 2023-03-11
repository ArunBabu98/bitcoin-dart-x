import 'package:bitcoin_dart_x/bip39/bip39.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:bitcoin_dart_x/bitcoin_dart_x.dart';
import 'package:hex/hex.dart';

void main() {
  test('BIP39 check', () {
    BIP39 bip39 = BIP39();
    var mnemonic = bip39.generateMnemonics(length: 24);
    var valid = bip39.validateMnemonic(mnemonic);
    expect(valid, true, reason: "Mnemonics is not valid!");
  });
}
