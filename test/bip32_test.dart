import 'package:bitcoin_dart_x/bip32/custom_networks/custom_networks.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Custom Network-bitcoin test', () {
    var custom = CustomNetworkTypes();
    var coin = custom.bitcoin;
    print(coin);
  });
}
