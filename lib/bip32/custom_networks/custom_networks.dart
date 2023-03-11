import '../bip32.dart';

class CustomNetworkTypes {
  /// network type for bitcoin.
  final NetworkType _BITCOIN = NetworkType(
      messagePrefix: '\x18Bitcoin Signed Message:\n',
      bech32: 'bc',
      bip32: Bip32Type(public: 0x0488b21e, private: 0x0488ade4),
      pubKeyHash: 0x00,
      scriptHash: 0x05,
      wif: 0x80);

  get bitcoin => _BITCOIN;
}
