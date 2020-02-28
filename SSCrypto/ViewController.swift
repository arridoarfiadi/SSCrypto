//
//  ViewController.swift
//  SSCrypto
//
//  Created by Arrido Arfiadi on 2/25/20.
//  Copyright © 2020 Arrido Arfiadi. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
	@IBOutlet weak var privateKeyTextView: NSTextView!
	@IBOutlet weak var cipherTextTextView: NSTextView!
	@IBOutlet weak var decryptedTextView: NSTextView!
	
	@IBOutlet weak var pubicKeyTextView: NSTextView!
	@IBOutlet weak var plainTextTextView: NSTextView!
	@IBOutlet weak var encryptedTextView: NSTextView!
	
	override func viewDidLoad() {
		super.viewDidLoad()
		decryptedTextView.isEditable = false
		encryptedTextView.isEditable = false
	}
	
	@IBAction func decryptButtonClicked(_ sender: Any) {
		if let decryptedText = cipherTextTextView.string.decrypt(using: privateKeyTextView.string.makeSingleLine()) {
			decryptedTextView.string = decryptedText
		} else {
			decryptedTextView.string = "Unable to decrypt"
		}
	}
	
	@IBAction func encryptButtonClicked(_ sender: Any) {
		if let encryptedText = plainTextTextView.string.encrypt(using: pubicKeyTextView.string.makeSingleLine()) {
			encryptedTextView.string = encryptedText
		} else {
			encryptedTextView.string = "Unable to encrypt"
		}
	}
	
}

class SMCryptography {
	internal let KEY_SIZE = 3072
	internal let KEY_TYPE = kSecAttrKeyTypeRSA
	internal let ALGORITHM: SecKeyAlgorithm = .rsaEncryptionOAEPSHA512AESGCM
}


class SMDecryptor:SMCryptography {
	private let privateKeyString: String
	private var PRIVATE_ATTRIBUTES: [String: Any] {
		return [
			kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
			kSecAttrKeyType as String: KEY_TYPE,
			kSecAttrKeySizeInBits as String: KEY_SIZE,
		]
	}
	
	init(privateKeyString: String) {
		self.privateKeyString = privateKeyString
	}
	
	func decrypt(_ cfData: CFData) -> CFData? {
		guard let secKeyData = Data(base64Encoded: privateKeyString), let secKey = SecKeyCreateWithData(secKeyData as CFData, PRIVATE_ATTRIBUTES as CFDictionary, nil) else {return nil}
		guard let decrypted = SecKeyCreateDecryptedData(secKey, ALGORITHM, cfData, nil) else {return nil}
		return decrypted
	}
}

class SMEncryptor: SMCryptography {
	private let publicKeyString: String
	private var PUBLIC_ATTRIBUTES: [String: Any] {
		return [
			kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
			kSecAttrKeyType as String: KEY_TYPE,
			kSecAttrKeySizeInBits as String: KEY_SIZE,
		]
	}
	
	init(publicKeyString: String) {
		self.publicKeyString = publicKeyString
	}
	
	func encrypt(_ cfData: CFData) -> CFData? {
		guard let secKeyData = Data(base64Encoded: publicKeyString), let secKey = SecKeyCreateWithData(secKeyData as CFData, PUBLIC_ATTRIBUTES as CFDictionary, nil) else {return nil}
		guard let cipherText = SecKeyCreateEncryptedData(secKey, ALGORITHM, cfData, nil) else {return nil}
		return cipherText
	}
}

extension String {
	func decrypt(using privateKeyString: String) -> String? {
		guard let data = Data(base64Encoded: self) as CFData? else {return nil}
		guard let decryptedData = SMDecryptor(privateKeyString: privateKeyString).decrypt(data) else {return nil}
		return String(decoding: decryptedData as Data, as: UTF8.self)
	}
	
	func encrypt(using publicKeyString: String) -> String? {
		guard let data = self.description.data(using: .utf8) as CFData? else {return nil}
		guard let cipherData = SMEncryptor(publicKeyString: publicKeyString).encrypt(data) else {return nil}
		return (cipherData as Data).base64EncodedString()
	}
	
	func makeSingleLine() -> String  {
		var newString = ""
		for line in self.split(whereSeparator: {$0.isNewline}) {
			newString += line.replacingOccurrences(of: " ", with: "")
		}
		return newString
	}
}


