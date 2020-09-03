//
//  OpenSSL4SwiftTests.swift
//  OpenSSL4SwiftTests
//
//  Created by User on 8/28/20.
//  Copyright © 2020 R&F Consulting, Inc. All rights reserved.
//

import XCTest

// WARNING: uses "OpenSSL4SwiftTests-Bridging-Header.h" vs. "OpenSSL4Swift-Bridging-Header.h"

fileprivate extension Bundle
{
	func extract(resource name: String, withExtension ext: String) -> String
	{
		let url = self.url(forResource: name, withExtension: ext)
		if let url = url, let resource = try? String(contentsOf: url) { return resource }
				
		fatalError("cannot extract a bundle resource [\(String(describing: url))]")
	}
}

class OpenSSL4SwiftTests: XCTestCase
{
	/*

	HOW TO GENERATE A PUBLIC/PRIVATE KEY PAIR

	https://rietta.com/blog/openssl-generating-rsa-key-from-command/
		
	openssl genrsa -des3 -out private.pem 2048
	openssl rsa -in private.pem -outform PEM -pubout -out public_key.pem
	openssl rsa -in private.pem -out private_key_unencrypted.pem -outform PEM

	*/

	override class func setUp()
	{
		// load public and private keys
		
		var publicKey: OpenSSL4Swift.PublicKey?
		XCTAssertNoThrow(publicKey = try OpenSSL4Swift.PublicKey(from:
			Bundle.main.extract(resource: "public_key", withExtension: "pem")))
			
		self.publicKey = publicKey
		
		//
		
		var privateKey: OpenSSL4Swift.PrivateKey?
		XCTAssertNoThrow(privateKey = try OpenSSL4Swift.PrivateKey(from:
			Bundle.main.extract(resource: "private_key_unencrypted", withExtension: "pem")))

		self.privateKey = privateKey
	}

	func test001() throws
	{
		// detect invalid public and private keys
		
		var publicKey: OpenSSL4Swift.PublicKey?
		XCTAssertThrowsError(publicKey = try OpenSSL4Swift.PublicKey(from: "0123456789"))
		
		XCTAssertNil(publicKey)
		
		//
		
		var privateKey: OpenSSL4Swift.PrivateKey?
		XCTAssertThrowsError(privateKey = try OpenSSL4Swift.PrivateKey(from: "9876543210"))
		
		XCTAssertNil(privateKey)
	}

	func test002() throws
	{
		// encrypt/decrypt

		XCTAssertNotNil(OpenSSL4SwiftTests.publicKey)
		XCTAssertNotNil(OpenSSL4SwiftTests.privateKey)
		
		guard
			let publicKey = OpenSSL4SwiftTests.publicKey, let privateKey = OpenSSL4SwiftTests.privateKey
				else { return }

		let plaintext = OpenSSL4SwiftTests.secret.data(using: .utf8)
		
		XCTAssertNotNil(plaintext)
		XCTAssert(plaintext?.count ?? 0 > 0)
		
		if let plaintext = plaintext
		{
			var ciphertext: Data?
			XCTAssertNoThrow(ciphertext = try OpenSSL4Swift.encrypt(publicKey: publicKey, plaintext: plaintext))

			XCTAssertNotNil(ciphertext)
			XCTAssert(ciphertext?.count ?? 0 > 0)
			
			if let ciphertext = ciphertext, ciphertext.count > 0
			{
				var outtext: Data?
				XCTAssertNoThrow(outtext = try OpenSSL4Swift.decrypt(privateKey: privateKey, ciphertext: ciphertext))
				
				if let outtext = outtext
				{
					XCTAssert(outtext == plaintext)
					XCTAssertEqual(OpenSSL4SwiftTests.secret, String(decoding: outtext, as: UTF8.self))
				}
			}
		}
	}
	
	func test003() throws
	{
		// detect encryption buffer overflow
		
		XCTAssertNotNil(OpenSSL4SwiftTests.publicKey)
		
		guard let publicKey = OpenSSL4SwiftTests.publicKey else { return }

		let plaintext: Data? =
		{
			// RSA asymetric encryption is meant for small blocks of data; encrypt large data
			// with a random symmetric key and encrypt that key with an RSA public key
			let size: Int = numericCast(publicKey.blockSize + 1)
			var data = Data(count: size)
			
			// generate cryptographically secure random bytes
			let rc = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!) }
			
			return rc == errSecSuccess ? data : nil
		}()
		
		XCTAssertNotNil(plaintext)
		XCTAssert(plaintext?.count ?? 0 > publicKey.blockSize)
		
		if let plaintext = plaintext
		{
			var ciphertext: Data?
			XCTAssertThrowsError(ciphertext = try OpenSSL4Swift.encrypt(publicKey: publicKey, plaintext: plaintext))

			XCTAssertNil(ciphertext)
		}
	}
	
	func test004() throws
	{
		// detect decryption padding mismatch

		XCTAssertNotNil(OpenSSL4SwiftTests.publicKey)
		XCTAssertNotNil(OpenSSL4SwiftTests.privateKey)
		
		guard
			let publicKey = OpenSSL4SwiftTests.publicKey, let privateKey = OpenSSL4SwiftTests.privateKey
				else { return }

		let plaintext = OpenSSL4SwiftTests.secret.data(using: .utf8)
		
		XCTAssertNotNil(plaintext)
		XCTAssert(plaintext?.count ?? 0 > 0)
		
		if let plaintext = plaintext
		{
			var ciphertext: Data?
			XCTAssertNoThrow(ciphertext = try OpenSSL4Swift.encrypt(publicKey: publicKey, plaintext: plaintext,
				paddingScheme: /* padding mismatch */ RSA_PKCS1_OAEP_PADDING))

			XCTAssertNotNil(ciphertext)
			XCTAssert(ciphertext?.count ?? 0 > 0)
			
			if let ciphertext = ciphertext, ciphertext.count > 0
			{
				var outtext: Data?
				XCTAssertThrowsError(outtext = try OpenSSL4Swift.decrypt(privateKey: privateKey, ciphertext: ciphertext,
					paddingScheme: /* padding mismatch */ RSA_SSLV23_PADDING))
				
				XCTAssertNil(outtext)
			}
		}
	}
	
	// MARK: - private
	
	private static var publicKey: OpenSSL4Swift.PublicKey?
	private static var privateKey: OpenSSL4Swift.PrivateKey?
	
	private static let secret = "pack my box with five dozen liquor jugs" // a pangram
}
