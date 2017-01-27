//
//  ViewController.swift
//  MasterKeyEncryption
//
//  Created by woroninb on 11/01/17.
//  Copyright © 2017 Swifting. All rights reserved.
//

import UIKit
import CryptoSwift

// Pre requirements and notes:
// - when you compiling this project on Simulator what you need to do is adding the "Share keychain entitlement
// - main goal of this project is to show main steps in encryption and decryption process based on AES algorithm
// - remember not to create your own crypto! Recomendation is to use libararies/components RNCryptor
// - this project is a part of post: https://swifting.io/blog/2017/01/16/33-security-implement-your-own-encryption-schema/
// - project was improved based on Rob Napier feedback

class ViewController: UIViewController {
    
    let keychain = KeychainSwift()

    override func viewDidLoad() {
        super.viewDidLoad()
        
        var derivedKey: Array<UInt8>!
        var masterKey: Array<UInt8>!
        var decryptedMasterKey: Array<UInt8>!
        var encryptedMasterKeyData: Data!
        let password = "test123".utf8.map {$0}
        
        //************************************************
        //Master key, derived key, salt and IV generation
        //************************************************
        print("----Master key, derived key, salt and IV generation----")
    
        //1. Generating salt
        // - is a random hash
        // - The salt does not need to be secret
        // - A new random salt must be generated each time a user creates an account or changes their password
        let salt = Array<UInt8>(generateSalt(length: 16)!)
        print("Salt: " + salt.toHexString())
        
        //2. Derive key generation
        // - using PBKDF2 256 bit, 32 bytes
        // - Apple acknowledges that it uses 10,000 iterations of PBKDF2 as part of the keybag design
        // - This key will be used to encrypt a master encrypion key
        do {
            derivedKey = try PKCS5.PBKDF2(password: password, salt: salt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            print("Derived Key: " + derivedKey.toHexString())
        } catch {
            print(error)
        }
        
        //3. Genereting random master key
        // - Never needs to change if it is protected at all times
        masterKey = Array<UInt8>(generateSalt(length: 32)!)
        print("Master Key: " + masterKey.toHexString())
        
        //4. Genereting IV
        // - should be a random data
        let iv: Array<UInt8> = AES.randomIV(AES.blockSize)
        print("IV: " + iv.toHexString())
        
        //5. Encrypt master key
        // - using AES-256
        // - CBC Mode
        do {
            let aes = try AES(key: derivedKey, iv: iv, blockMode: .CBC, padding: PKCS7())
            let encryptedMasterKey = try aes.encrypt(masterKey)
            encryptedMasterKeyData = Data(bytes: encryptedMasterKey) //coverted to Data to store in keychain
        } catch {
            print(error)
        }
    
        //6. Store encrypted master key in keychain
        // - format(Salt:IV:EncryptedMasterKeyData)
        let encryptedSaltIVMasterKey =
            salt.toBase64()! + ":" +
            iv.toBase64()! + ":" +
            encryptedMasterKeyData.base64EncodedString()
        keychain.set(encryptedSaltIVMasterKey, forKey: "masterKey")
        
        //************************************************
        //Encryption of some example data
        //************************************************
        print("----Encryption of some example data----")
        
        let login = "login"
        var encryptedLogin: Array<UInt8>!
        var reCalculatedDerivedKey: Array<UInt8>!
        let hmacSalt: Array<UInt8>! = generateSalt(length: 16)!.bytes
        let loginIV: Array<UInt8>! = AES.randomIV(AES.blockSize)
        var hmac: Array<UInt8>!
        
        //1. Get encrypted master Key from keychain
        // - format(Salt:IV:EncryptedMasterKeyData)
        let savedEncryptedSaltIVMasterKey = keychain.get("masterKey")!.components(separatedBy: ":")
        let savedSalt = (Data(base64Encoded: savedEncryptedSaltIVMasterKey[0])?.bytes)!
        let savedIV = (Data(base64Encoded: savedEncryptedSaltIVMasterKey[1])?.bytes)!
        let savedEncryptedMasterKey = (Data(base64Encoded: savedEncryptedSaltIVMasterKey[2])?.bytes)!
        
        //2. Recalculating Derived Key
        // - user is authenticated so application knows his pin
        do {
            reCalculatedDerivedKey = try PKCS5.PBKDF2(password: password, salt: savedSalt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            print("Realculated Derived Key: " + reCalculatedDerivedKey.toHexString())
        } catch {
            print(error)
        }
        
        //3. Decrypt MasterKey
        do {
            let aes = try AES(key: reCalculatedDerivedKey, iv: savedIV, blockMode: .CBC, padding: PKCS7())
            decryptedMasterKey = try aes.decrypt(savedEncryptedMasterKey)
            print("Decrypted Master Key: " + decryptedMasterKey.toHexString())
        } catch {
            print(error)
        }
        
        //4. Encrypt data using AES with Master Key
        do {
            let aes = try AES(key: decryptedMasterKey, iv: loginIV, blockMode: .CBC, padding: PKCS7())
            encryptedLogin = try aes.encrypt(login.utf8.map({$0}))
        } catch {
            print(error)
        }
        
        //5. Genereting HMAC
        // - Creating header message
        // - format(hmacSalt:loginIV:encryptedLogin:HMAC)
        let headerMessage =
            (hmacSalt.toBase64()! + ":" +
            loginIV.toBase64()! + ":" +
            encryptedLogin.toBase64()!)
        do {
            let hmacKey = try PKCS5.PBKDF2(password: password, salt: hmacSalt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            hmac = try HMAC(key: hmacKey, variant: .sha256).authenticate((headerMessage.data(using: .utf8)!.bytes))
            print("HMAC: " + hmac.toHexString())
        } catch {
            print(error)
        }
        
        //6. Strore data in database
        // - Here in example we store data in keychain for show case purposes.
        let message = headerMessage + ":" + hmac.toBase64()!
        keychain.set(message, forKey: "login")
        
        //************************************************
        //Decryption of some example data
        //************************************************
        print("----Decryption of some example data----")
        
        //6. Get data from store
        let savedMessage = keychain.get("login")?.components(separatedBy: ":")
        let savedhmacSalt = (Data(base64Encoded: (savedMessage?[0])!)?.bytes)!
        let savedLoginIV = (Data(base64Encoded: (savedMessage?[1])!)?.bytes)!
        let savedEncryptedLogin = (Data(base64Encoded: (savedMessage?[2])!)?.bytes)!
        let savedHMAC = (Data(base64Encoded: (savedMessage?[3])!)?.bytes)!
        
        //7. User inputs his passphrase and message is authenticated
        do {
            let hmacKey = try PKCS5.PBKDF2(password: password, salt: savedhmacSalt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            hmac = try HMAC(key: hmacKey, variant: .sha256).authenticate((headerMessage.data(using: .utf8)!.bytes))
            if(hmac == savedHMAC) {
                print("Message is authenticated")
            }
        } catch {
            print(error)
        }
        
        //8. Decrypt data
        do {
            let aes = try AES(key: decryptedMasterKey, iv: savedLoginIV, blockMode: .CBC, padding: PKCS7())
            let decryptedLogin = try aes.decrypt(savedEncryptedLogin)
            
            if let decryptedLoginString = String(bytes: decryptedLogin, encoding: .utf8) {
                print("Decrypted data: " + decryptedLoginString)
            } else {
                print("not a valid UTF-8 sequence")
            }
        } catch {
            print(error)
        }
        
        //************************************************
        //Change password scenerio
        //************************************************
        print("----Change password scenerio----")
    
        //if the user should change his password the master key can be simply re-encrypted with the new derivedKey whereas you'd have to re-encrypt all of the user's data if the password were tied directly to the encrypted data
        let newPassword = "pass1234".utf8.map {$0}
        
        //1. Get encrypted master Key from keychain
        // - format(Salt:IV:EncryptedMasterKeyData)
        let savedMasterKeyMessage = keychain.get("masterKey")!.components(separatedBy: ":")
        let savedOldSalt = (Data(base64Encoded: savedMasterKeyMessage[0])?.bytes)!
        let savedOldIV = (Data(base64Encoded: savedMasterKeyMessage[1])?.bytes)!
        let encryptedMasterKey = (Data(base64Encoded: savedMasterKeyMessage[2])?.bytes)!
        
        //2. Recalculating Derived Key
        do {
            reCalculatedDerivedKey = try PKCS5.PBKDF2(password: password, salt: savedOldSalt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            print("Realculated Derived Key: " + reCalculatedDerivedKey.toHexString())
        } catch {
            print(error)
        }
        
        //3. Decrypt MasterKey
        // - user input his old password first, so we can decrypt masterKey
        do {
            let aes = try AES(key: reCalculatedDerivedKey, iv: savedOldIV, blockMode: .CBC, padding: PKCS7())
            decryptedMasterKey = try aes.decrypt(encryptedMasterKey)
            print("Decrypted Master Key: " + decryptedMasterKey.toHexString())
        } catch {
            print(error)
        }
        
        //5. New Salt
        let newSalt = Array<UInt8>(generateSalt(length: 16)!)
        print("New Salt: " + newSalt.toHexString())
        
        //6. New derived Key
        var newDerivedKey: Array<UInt8>!
        do {
            newDerivedKey = try PKCS5.PBKDF2(password: newPassword, salt: newSalt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            print("New Derived Key: " + newDerivedKey.toHexString())
        } catch {
            print(error)
        }
        
        //7. Generating new IV
        let newIV = AES.randomIV(AES.blockSize)
        
        //8. Re-encrypting Master key
         do {
            let aes = try AES(key: newDerivedKey, iv: newIV, blockMode: .CBC, padding: PKCS7())
            let encryptedMasterKey = try aes.encrypt(decryptedMasterKey)
            encryptedMasterKeyData = Data(bytes: encryptedMasterKey) //coverted to Data to store in keychain
        } catch {
            print(error)
        }
    
        //10. Store new encrypted master key in keychain
        let newEncryptedSaltIVMasterKey =
            newSalt.toBase64()! + ":" +
            newIV.toBase64()! + ":" +
            encryptedMasterKeyData.base64EncodedString()

        keychain.set(newEncryptedSaltIVMasterKey, forKey: "masterKey")
        
        //11. That's all we don't need to re-encrypt all previously encypted data
        
    }
    
    //Salt generating funcion according to Mobile hackers handbook
    // - never reuse salt
    // - recommended 32 bytes of length
    
    func generateSalt(length: Int) -> Data? {
        
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, data.count, mutableBytes)
        }
        
        if(result != 0) {
            print("Unable to generate salt")
            return nil
        }
        
        return data
    }


    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
}

