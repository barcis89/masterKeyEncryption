//
//  ViewController.swift
//  MasterKeyEncryption
//
//  Created by woroninb on 11/01/17.
//  Copyright © 2017 Swifting. All rights reserved.
//

import UIKit
import CryptoSwift

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
        //Master key, derived key and salt generation
        //************************************************
        
        // Pre requirements:
        // - when you compiling this project on Simulator what you need to do is adding the "Share keychain entitlement
        
        //Generating salt:
        // - is a random hash
        // - The salt does not need to be secret
        // - A new random salt must be generated each time a user creates an account or changes their password
        // - Generate 256 bit sequence, 32 bytes
        let salt = Array<UInt8>(generateSalt(length: 32)!)
        
        // Derive key generation:
        // - using PBKDF2 256 bit, 32 bytes
        // - Apple acknowledges that it uses 10,000 iterations of PBKDF2 as part of the keybag design
        // - This key will be used to encrypt a master encrypion key
        do {
            derivedKey = try PKCS5.PBKDF2(password: password, salt: salt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            print(derivedKey)
        } catch {
            print(error)
        }
        
        //Genereting random master key:
        // - Never needs to change if it is protected at all times
        masterKey = Array<UInt8>(generateSalt(length: 32)!)
        
        //Encrypt master key:
        // - using AES-256
        // - AES-XTS with a key size of 256 is widely accepted as being suitable for most use cases for mobile applications.
        do {
            let aes = try AES(key: derivedKey)
            let encryptedMasterKey = try aes.encrypt(masterKey)
            encryptedMasterKeyData = Data(bytes: encryptedMasterKey) //coverted to Data to store in keychain
            print(encryptedMasterKey)
        } catch {
            print(error)
        }
        
        //Store encrypted master key in keychain
        keychain.set(encryptedMasterKeyData, forKey: "masterKey")
        
        //************************************************
        //Encryption and decription of some example data
        //************************************************
        
        let login = "login"
        var encryptedLogin: Array<UInt8>!
        
        //1 - Decrypt MasterKey
        do {
            let encryptedMasterKey = keychain.getData("masterKey")!.bytes
            //user is authenticated so application knows his pin
            decryptedMasterKey = try AES(key: derivedKey).decrypt(encryptedMasterKey)
        } catch {
            print(error)
        }
        
        //2 - Encrypt data using AES with masterkey
        do {
            encryptedLogin = try AES(key: decryptedMasterKey).encrypt(login.utf8.map({$0}))
            print(encryptedLogin)
        } catch {
            print(error)
        }
        
        //3 - Decrypt example data
        do {
            let decryptedLogin = try AES(key: decryptedMasterKey).decrypt(encryptedLogin)
            
            if let str = String(bytes: decryptedLogin, encoding: .utf8) {
                print(str)
            } else {
                print("not a valid UTF-8 sequence")
            }
        } catch {
            print(error)
        }
        
        //************************************************
        //Change password scenerio
        //************************************************
        
        //if the user should change his password the master key can be simply re-encrypted with the new derivedKey whereas you'd have to re-encrypt all of the user's data if the password were tied directly to the encrypted data
        
        //1 - new derived key
        var newDerivedKey: Array<UInt8>!
        let newPassword = "pass1234".utf8.map {$0}
        
        //Remember: never reuse salt !!!
        let newSalt = Array<UInt8>(generateSalt(length: 16)!)
        
        do {
            newDerivedKey = try PKCS5.PBKDF2(password: newPassword, salt: newSalt, iterations: 10_000, keyLength: 32, variant: .sha256).calculate()
            print(newDerivedKey)
        } catch {
            print(error)
        }
        
        //2 - user input his old password first, so we can decrypt masterKey
        do {
            let encryptedMasterKey = keychain.getData("masterKey")!.bytes
            //user is authenticated so application knows his pin
            decryptedMasterKey = try AES(key: derivedKey).decrypt(encryptedMasterKey)
        } catch {
            print(error)
        }
        
        //3 - re-encrypting master key
        do {
            let aes = try AES(key: newDerivedKey)
            let encryptedMasterKey = try aes.encrypt(decryptedMasterKey)
            encryptedMasterKeyData = Data(bytes: encryptedMasterKey) //converted to Data to store in keychain
            print(encryptedMasterKey)
        } catch {
            print(error)
        }
        
        //4 - store new encrypted master key in keychain
        
        keychain.set(encryptedMasterKeyData, forKey: "masterKey")
        
        //5 - that's all we don't need to re-encrypt all previously encypted data
        
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

