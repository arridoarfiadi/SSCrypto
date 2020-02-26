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
	
	override func viewDidLoad() {
		super.viewDidLoad()
		decryptedTextView.isEditable = false
		// Do any additional setup after loading the view.
	}

	override var representedObject: Any? {
		didSet {
		// Update the view, if already loaded.
		}
	}
	
	@IBAction func decryptButtonClicked(_ sender: Any) {
		if let decryptedText = cipherTextTextView.string.decrypt(using: privateKeyTextView.string) {
			decryptedTextView.string = decryptedText
		} else {
			decryptedTextView.string = "Unable to decrypt"
		}
	}
	
}


class SMDecryptor {
	private let KEY_SIZE = 2048
	private let KEY_TYPE = kSecAttrKeyTypeRSA
	private let privateKeyString: String
		
	private let ALGORITHM: SecKeyAlgorithm = .rsaEncryptionOAEPSHA512AESGCM

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

extension String {
	func decrypt(using privateKeyString: String) -> String? {
		guard let data = Data(base64Encoded: self) as CFData? else {return nil}
		guard let decryptedData = SMDecryptor(privateKeyString: privateKeyString).decrypt(data) else {return nil}
		return String(decoding: decryptedData as Data, as: UTF8.self)
	}
}


