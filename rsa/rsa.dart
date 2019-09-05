import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

Encrypted rsaEncrypt(Uint8List data, String publicKey) {
  final encrypter = Encrypter(RSA(publicKey: RSAKeyParser().parse(publicKey)));
  return encrypter.encryptBytes(data);
}

List<int> rsaDecrypt(Uint8List data, String privateKey) {
  final encrypted = new Encrypted(data);
  final encrypter =
      Encrypter(RSA(privateKey: RSAKeyParser().parse(privateKey)));
  return encrypter.decryptBytes(encrypted);
}

Uint8List randomBytes(int len) {
  return SecureRandom(len).bytes;
}

Encrypted aesEncrypt(Uint8List data, Uint8List key, Uint8List iv) {
  final encrypter = Encrypter(AES(Key(key)));
  return encrypter.encryptBytes(data, iv: IV(iv));
}

Uint8List aesDecrypt(Uint8List data, Uint8List key, Uint8List iv) {
  final encrypted = new Encrypted(data);
  final encrypter = Encrypter(AES(Key(key)));
  return Uint8List.fromList(encrypter.decryptBytes(encrypted, iv: IV(iv)));
}
