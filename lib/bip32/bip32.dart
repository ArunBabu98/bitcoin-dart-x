/* BIP-32 -  Hierarchical Deterministic Wallets */

import 'dart:convert';
import 'dart:typed_data';

import 'package:bitcoin_dart_x/bip32/custom_networks/custom_networks.dart';

import 'crypto.dart';

/// Provide version bytes for custom network types.
class NetworkType {
  String messagePrefix;
  String? bech32;
  Bip32Type bip32;
  int pubKeyHash;
  int scriptHash;
  int wif;

  NetworkType(
      {required this.messagePrefix,
      this.bech32,
      required this.bip32,
      required this.pubKeyHash,
      required this.scriptHash,
      required this.wif});

  @override
  String toString() {
    return 'NetworkType{messagePrefix: $messagePrefix, bech32: $bech32, bip32: ${bip32.toString()}, pubKeyHash: $pubKeyHash, scriptHash: $scriptHash, wif: $wif}';
  }
}

class Bip32Type {
  int public;
  int private;

  Bip32Type({required this.public, required this.private});

  @override
  String toString() {
    return 'Bip32Type{public: $public, private: $private}';
  }
}

const HIGHEST_BIT = 0x80000000;
const UINT31_MAX = 2147483647; // 2^31 - 1
const UINT32_MAX = 4294967295; // 2^32 - 1

/// Implementation of Bitcoin Improvement Proposal 32
class BIP32 {
  Uint8List? _d; // private key (from curve)
  Uint8List? _Q; // public key calculated by EC.
  Uint8List chainCode;
  int depth = 0; // depth 0x00 for master node.
  int index = 0; // index is set to 0 initially
  NetworkType network;
  int parentFingerprint = 0x00000000; // 0 for master key

  BIP32(this._d, this._Q, this.chainCode, this.network);

  /// from private key : to do
  factory BIP32.fromPrivateKey(Uint8List privateKey, Uint8List chainCode,
      [NetworkType? nw]) {
    NetworkType network = nw ?? CustomNetworkTypes().bitcoin;
    if (privateKey.length != 32) {
      throw ArgumentError(
          "Expected property privateKey of type Buffer(Length: 32)");
    }
  }

  /// from Seed
  factory BIP32.fromSeed(Uint8List seed, {NetworkType? nw}) {
    if (seed.length < 16) {
      throw ArgumentError("Seed should be at least 128 bits");
    }
    if (seed.length > 64) {
      throw ArgumentError("Seed should be at most 512 bits");
    }
    NetworkType network = nw ?? CustomNetworkTypes().bitcoin;
    final I = hmacSHA512(utf8.encode("Bitcoin seed") as Uint8List, seed);
    final IL = I.sublist(0, 32);
    final IR = I.sublist(32);
    return BIP32.fromPrivateKey(IL, IR, network);
  }
}
