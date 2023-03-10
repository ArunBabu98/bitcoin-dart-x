/* BIP-39 - Mnemonic code for generating deterministic keys */

import 'dart:math';

import 'package:bitcoin_dart_x/bip39/utils/pbkdf2.dart';
import 'package:bitcoin_dart_x/bip39/wordlists/english.dart';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

class BIP39 {
  // wordlist currently only supports english language
  List WORDLIST = englishList;

  // Number of words to entropy bits length
  Map<int, int> MS_TO_ENT = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256};

  // converts bytes into binary

  String _bytesToBinary(Uint8List bytes) {
    return bytes.map((byte) => byte.toRadixString(2).padLeft(8, '0')).join('');
  }

  // converts binary to bytes

  int _binaryToByte(String binary) {
    return int.parse(binary, radix: 2);
  }

  /* Entropy length is multiplied by 8, to make it bit accurate. hash256 of the initial entropy is taken, and the checksum is derived by taking first 
    ENT/32 bits of the hash. For making the calculation easier the bytes are converted into binary. */
  String _deriveChecksumBits(Uint8List entropy) {
    final ENT = entropy.length * 8;
    final CS = ENT ~/ 32;
    final hash = sha256.convert(entropy);
    return _bytesToBinary(Uint8List.fromList(hash.bytes)).substring(0, CS);
  }

  /// Generates the mnemonics. Optional [length] can be 12, 15, 18, 21 or 24. Only english wordlists are supported currently.
  generateMnemonics({int length = 12}) {
    if (!MS_TO_ENT.containsKey(length)) {
      throw Exception("Mnemonic word length must be [12, 15, 18, 21, 24]");
    }
    int ENT = MS_TO_ENT[length]!;
    int size = ENT ~/ 8; // byte calculation.
    Random random = Random.secure();
    // intial entropy
    final entropy = Uint8List(size);
    for (int i = 0; i < size; i++) {
      entropy[i] = random.nextInt(255);
    }
    if (entropy.length < 16 || entropy.length > 32) {
      throw Exception("Entropy length invalid");
    }
    String entropyBits = _bytesToBinary(entropy);
    int CS = (ENT * 8) ~/ 32;
    final hash = sha256.convert(entropy);
    String checksum = _deriveChecksumBits(entropy);
    String newBits = entropyBits + checksum;
    // regex to split the string into sets of 11 bits
    final regex = RegExp(r".{1,11}", caseSensitive: false, multiLine: false);
    List<String> chunks = regex
        .allMatches(newBits)
        .map((match) => match.group(0)!)
        .toList(growable: false);
    String mnemonics =
        chunks.map((binary) => WORDLIST[_binaryToByte(binary)]).join(' ');
    return mnemonics;
  }

  /// Returns a 512 bits seed from the mnemonics. Passphrase is optional.
  Uint8List mnemonicToSeed(String mnemonic, {String passphrase = ""}) {
    final pbkdf2 = PBKDF2();
    return pbkdf2.process(mnemonic, passphrase: passphrase);
  }

  /// Returns the entropy, given the mnemonic
  String mnemonicToEntropy(String mnemonic) {
    List<String> words = mnemonic.split(' ');
    if (!MS_TO_ENT.containsKey(words.length)) {
      throw Exception("Mnemonic word length must be [12, 15, 18, 21, 24]");
    }
    String bits = words.map((word) {
      final index = WORDLIST.indexOf(word);
      if (index == -1) {
        throw Exception("Invalid Mnemonic!");
      }
      return index.toRadixString(2).padLeft(11, '0');
    }).join('');
    // split the binary string into ENT/CS
    final dividerIndex = (bits.length / 33).floor() * 32;
    final entropyBits = bits.substring(0, dividerIndex);
    final checksumBits = bits.substring(dividerIndex);
    // calculate the checksum and compare
    final regex = RegExp(r".{1,8}");
    final entropyBytes = Uint8List.fromList(regex
        .allMatches(entropyBits)
        .map((match) => _binaryToByte(match.group(0)!))
        .toList(growable: false));
    if (entropyBytes.length < 16) {
      throw Exception("Invalid entropy!");
    }
    if (entropyBytes.length > 32) {
      throw Exception("Invalid entropy!");
    }
    if (entropyBytes.length % 4 != 0) {
      throw Exception("Invalid entropy!");
    }
    final newChecksum = _deriveChecksumBits(entropyBytes);
    if (newChecksum != checksumBits) {
      throw Exception("Invalid Checksum!");
    }
    return entropyBytes.map((byte) {
      return byte.toRadixString(16).padLeft(2, '0');
    }).join('');
  }

  /// Checks wether the mnemonic is valid or not. Returns true if it is, else returns false.
  bool validateMnemonic(String mnemonic) {
    try {
      mnemonicToEntropy(mnemonic);
    } catch (e) {
      return false;
    }
    return true;
  }
}
