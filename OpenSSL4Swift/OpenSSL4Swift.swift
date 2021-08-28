//
//  OpenSSL4Swift.swift
//  OpenSSL4Swift
//
//  Created by User on 8/24/20.
//  Copyright © R&F Consulting, Inc. All rights reserved.
//

import Foundation

public protocol OpenSSL4Swift_RSAKey {
	var rsa: UnsafeMutablePointer<RSA>? { get }
	var blockSize: /* unsigned */ UInt { get }
}

public enum /* namespace */ OpenSSL4Swift {
	// failure points

	public typealias ErrorCode = UInt

	public /* recursive */ indirect enum Failure: Error { // LocalizedError available in an extension
		case
			/* key */ utf8DecodeError,
			/* encrypt */ blockSizeOverflow,
			/* decrypt */ blockSizeMismatch,
			/* OpenSSL */ libError(api: String, code: ErrorCode? = nil, message: String? = nil, next: Failure? = nil)
	}

	// cannot nest a protocol (an interface) inside an enum (a namespace)
	typealias RSAKey = OpenSSL4Swift_RSAKey

	public class PublicKey: RSAKey {
		public /* consumers: r/o */ internal(set) var rsa: UnsafeMutablePointer<RSA>?

		init(from text: String) throws { // a failable initializer would be too vague
			guard let keyData = text.data(using: .utf8) else { throw Failure.utf8DecodeError }
			let keyBIO = try RSABIO(from: keyData)

			guard let rsa = PEM_read_bio_RSA_PUBKEY(keyBIO.bio, nil, nil, nil), ERR_peek_error() == 0
				else { throw earliestLibError(api: "PEM_read_bio_RSA_PUBKEY") }

			self.rsa = rsa
		}
		
		deinit {
			if rsa != nil { RSA_free(rsa) }
		}
	}

	public class PrivateKey: RSAKey {
		public internal(set) var rsa: UnsafeMutablePointer<RSA>?

		init(from text: String) throws {
			guard let keyData = text.data(using: .utf8) else { throw Failure.utf8DecodeError }
			let keyBIO = try RSABIO(from: keyData)

			guard let rsa = PEM_read_bio_RSAPrivateKey(keyBIO.bio, nil, nil, nil), ERR_peek_error() == 0
				else { throw earliestLibError(api: "PEM_read_bio_RSAPrivateKey") }
			
			self.rsa = rsa
		}
		
		deinit {
			if rsa != nil { RSA_free(rsa) }
		}
	}

	// processors

	public static func encrypt(publicKey: PublicKey, plaintext: Data,
			paddingScheme: Int32 = defaultRSAPaddingScheme) throws -> /* ciphertext */ Data? {
		// convert: UnsafeRawPointer >> UnsafePointer<T>
		let plaintextDataPtr = (plaintext as NSData).bytes.assumingMemoryBound(to: UInt8.self)

		// RSA asymetric encryption is meant for small blocks of data; encrypt large data
		// with a random symmetric key and encrypt that key with an RSA public key
		let bufferSize = publicKey.blockSize
		guard numericCast(plaintext.count) <= bufferSize else { throw Failure.blockSizeOverflow }
		
		let ciphertextBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: numericCast(bufferSize))
		defer { ciphertextBuffer.deallocate() }

		// in/out: UnsafePointer<T> >> UnsafeMutablePointer<T>
		let ciphertextSize = RSA_public_encrypt(
			numericCast(plaintext.count), plaintextDataPtr, ciphertextBuffer, publicKey.rsa, paddingScheme)

		guard ciphertextSize >= 0, ERR_peek_error() == 0
			else { throw earliestLibError(api: "RSA_public_encrypt") }

		// UnsafeMutablePointer<T> >> Data
		return Data(bytes: /* will copy */ ciphertextBuffer, count: numericCast(ciphertextSize))
	}
	
	public static func decrypt(privateKey: PrivateKey, ciphertext: Data,
			paddingScheme: Int32 = defaultRSAPaddingScheme) throws -> /* plaintext */ Data? {
		let ciphertextSize = ciphertext.count
		guard numericCast(ciphertextSize) == privateKey.blockSize else { throw Failure.blockSizeMismatch }

		let plaintextBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: numericCast(ciphertextSize))
		defer { plaintextBuffer.deallocate() }

		// convert: UnsafeRawPointer >> UnsafePointer<T>
		let ciphertextDataPtr = (ciphertext as NSData).bytes.assumingMemoryBound(to: UInt8.self)

		// int/out: UnsafeMutablePointer<T> >> UnsafeMutablePointer<T>
		let plaintextSize = RSA_private_decrypt(
			numericCast(ciphertextSize), ciphertextDataPtr, plaintextBuffer, privateKey.rsa, paddingScheme)

		guard plaintextSize >= 0, ERR_peek_error() == 0
			else { throw earliestLibError(api: "RSA_private_decrypt") }
		
		// UnsafeMutablePointer<T> >> Data
		return Data(bytes: /* will copy */ plaintextBuffer, count: numericCast(plaintextSize))
	}

	/*

	USING PADDING
	
	http://marc.info/?l=openssl-users&m=99663988913005&w=2

	"the padding modes take less data than the modulus size and pad it out
	to the size of the modulus in such a way that the value is less than the
	modulus, the reason being that the top byte of the padded data is 0"

	---
	
	FYI: using RSA_SSLV23_PADDING for encryption results in RSA_PKCS1_PADDING under OpenSSL 1.0.1e

	---
	
	https://stackoverflow.com/questions/30365901/decryption-with-rsa-sslv23-padding-not-working
	"To use RSA_SSLV23_PADDING, I believe you call EVP_PKEY_CTX_set_rsa_padding on the EVP_PKEY_CTX*.
	See EVP_PKEY_CTX_ctrl man pages for details."

	---

	https://wiki.openssl.org/index.php/Manual:RSA_public_encrypt(3)
	RSA_PKCS1_OAEP_PADDING: EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter.
	This mode is recommended for all new applications.

	RSA_SSLV23_PADDING: PKCS #1 v1.5 padding with an SSL-specific modification that denotes that the server is SSL3 capable.

	---

	https://stackoverflow.com/questions/37333684/checking-data-signature-with-public-key-using-openssl

	*/

	public static let defaultRSAPaddingScheme = RSA_PKCS1_OAEP_PADDING

	// MARK: - private

	private class RSABIO { // an I/O stream abstraction
		public internal(set) var bio: UnsafeMutablePointer<BIO>?

		init(from keyData: Data) throws {
			guard let bio = BIO_new(BIO_s_mem()) else { throw earliestLibError(api: "BIO_new") }
			BIO_write(bio, (keyData as NSData).bytes, numericCast(keyData.count))
			self.bio = bio
		}
		
		deinit {
			if bio != nil { BIO_free(bio) }
		}
	}
	
	private static /* thus lazy */ let stringsLoaded: Bool = {
		// initializes arrays for the error-handling library with messages specific to the RSA library

		ERR_load_ERR_strings()
		ERR_load_RSA_strings() // otherwise: "error:0407109F:lib(4):func(113):reason(159)"
		ERR_load_PEM_strings()
		ERR_load_BIO_strings()
		
		return true
	}()

	private static func errorMessage(for errorCode: ErrorCode) -> String? {
		_ = self.stringsLoaded
	
		guard let nullTerminatedUTF8 = /* does not need dealloc */ ERR_error_string(errorCode, nil) else { return nil }
		return String(cString: /* will copy */ UnsafePointer<CChar>(nullTerminatedUTF8))
	}

	typealias ErrorQueue = [ErrorCode]
	
	private static func libErrors() -> ErrorQueue { // the EARLIEST error code first
		var errorCodes = ErrorQueue()

		while true {
			// returns the EARLIEST error code from the thread's error queue and removes the entry
			let errorCode = ERR_get_error()

			if errorCode == 0 { break } else { errorCodes.append(errorCode) }
		}
		
		return errorCodes
	}

	private static func earliestLibError(api: String) -> Failure { // the EARLIEST failure first
		let errorCodes = libErrors()

		/*

		rsa.h

		error:04072073:rsa routines:RSA_padding_check_SSLv23:sslv3 rollback attack
		error:04065072:rsa routines:RSA_EAY_PRIVATE_DECRYPT:padding check failed
		...

		*/

		// produce a single failure from a sequence of error codes, from LATEST back to EARLIEST
		let error = errorCodes.reversed().reduce(nil) { failure, errorCode in
			Failure.libError(api: api, code: errorCode, message: errorMessage(for: errorCode), next: failure)
		}

		return error ?? Failure.libError(api: api)
	}
}

extension OpenSSL4Swift_RSAKey
{
	public var blockSize: /* unsigned */ UInt {
		// the RSA modulus size in bytes; how much memory must be allocated for an RSA encrypted value
		return rsa != nil ? numericCast(RSA_size(rsa)) : 0
	}
}

extension OpenSSL4Swift.Failure: LocalizedError
{
	public var errorDescription: String? {
		switch self {
			case .utf8DecodeError:
				return NSLocalizedString("UTF-8 decode error", comment: "")
			
			case .blockSizeOverflow:
				return NSLocalizedString("encryption block size overflow", comment: "")
				
			case .blockSizeMismatch:
				return NSLocalizedString("decryption block size mismatch", comment: "")

			case .libError(let api, let code, let message, /* next failure */ _):
				return NSLocalizedString(
					"OpenSSL [\(api)] error, " +
					"error code: [\(code == nil ? "" : String(code!))], " +
					"message: [\(message == nil ? "" : message!)]", comment: "")
		}
	}
}
