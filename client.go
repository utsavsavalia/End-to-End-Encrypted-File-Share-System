package client

// You MUST NOT change these default imports.

import (
	"encoding/json"
	"fmt"

	//"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	//"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// 	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
// 	type Course struct {
// 		name      string
// 		professor []byte
// 	}

// 	course := Course{"CS 161", []byte("Nicholas Weaver")}
// 	courseBytes, err := json.Marshal(course)
// 	if err != nil {
// 		panic(err)
// 	}

// 	// Generate a random private/public keypair.
// 	// The "_" indicates that we don't check for the error case here.
// 	var pk userlib.PKEEncKey
// 	var sk userlib.PKEDecKey
// 	pk, sk, _ = userlib.PKEKeyGen()
// 	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

// 	// Here's an example of how to use HBKDF to generate a new key from an input key.
// 	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
// 	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
// 	// store one key and derive multiple keys from that one key, rather than
// 	originalKey := userlib.RandomBytes(16)
// 	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
// 	if err != nil {
// 		panic(err)
// 	}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username     string
	Password     string
	SecretKey    userlib.PKEDecKey
	SignatureKey userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Text        []byte
	NextPointer userlib.UUID
	TailPointer userlib.UUID
}

type SecureStore struct {
	Ciphertext []byte
	HMAC       []byte
	Signature  []byte
}

type PersonalLockbox struct {
	DecryptionKey        []byte
	FileOrLockBoxPointer userlib.UUID
	ListHMAC             []byte
	DecryptionListKey    []byte
	SharedUsersList      []byte
}

type Lockbox struct {
	DecryptionKey []byte
	EncFile       userlib.UUID
}

type InviteCarrier struct {
	DecryptionKey []byte
	//Signature     []byte
	HMAC      []byte
	EncInvite []byte
}

type Invitation struct {
	DecryptionKey     []byte
	EncLockboxPointer userlib.UUID
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	//Error if they provide an empty string for the username
	_ = fmt.Sprintf("%d", 1)
	if username == "" {
		return nil, errors.New("the username is empty. Please enter a username")
	}

	var _, keyExists = userlib.KeystoreGet(username)

	//Error if the username is already taken by another user
	if keyExists {
		return nil, errors.New("another user with this username already exists. please select a different username")
	}

	//Initializes and adds data for the new user
	var userdata User
	userdata.Username = username
	userdata.Password = password

	//Create the root key for the User
	var salt = userlib.Hash([]byte(username))
	var rootKey = userlib.Argon2Key([]byte(password), salt, 16)

	//Create the Public/Private key pair and add to Keystore
	var pubKey, secKey, err1 = userlib.PKEKeyGen()
	userdata.SecretKey = secKey
	userlib.KeystoreSet(username, pubKey)
	if err1 != nil {
		return nil, errors.New("Error1")
	}

	//Create the key pair for Signatures
	var sKey, vKey, err2 = userlib.DSKeyGen()
	userdata.SignatureKey = sKey
	userlib.KeystoreSet(username+"Verify Key", vKey)
	if err2 != nil {
		return nil, errors.New("Error2")
	}

	//Create a Secure Store struct
	var secureStore SecureStore

	//Encrypt the pointer to the user struct
	var iv = userlib.RandomBytes(16)
	var encryptionKey, err3 = userlib.HashKDF(rootKey, []byte("User Struct"))
	var byteData, err4 = json.Marshal(userdata)
	var encryptedPointer = userlib.SymEnc(encryptionKey[:16], iv, byteData)
	if (err3 != nil) || (err4 != nil) {
		return nil, errors.New("error")
	}

	//Store ciphertext in secure struct
	secureStore.Ciphertext = encryptedPointer

	//HMAC the encrypted pointer and store in File struct
	var userHMACKey, err18 = userlib.HashKDF(rootKey, []byte("User Struct HMAC Key"))
	var userHMAC, err5 = userlib.HMACEval(userHMACKey[:16], encryptedPointer)
	secureStore.HMAC = userHMAC
	if (err5 != nil) || (err18 != nil) {
		return nil, errors.New("Error3")
	}

	// Encrypt the secureStore
	var secureStoreByte, err6 = json.Marshal(secureStore)
	iv = userlib.RandomBytes(16)
	var secureStoreKey, err7 = userlib.HashKDF(rootKey, []byte("Secure User Struct Key"))
	var secureStoreEnc = userlib.SymEnc(secureStoreKey[:16], iv, secureStoreByte)
	if (err6 != nil) || (err7 != nil) {
		return nil, errors.New("Error4")
	}

	//Store encrypted secure struct in Datastore
	var datastoreKey, err8 = userlib.HashKDF(rootKey, []byte("Secure User Struct Datastore Key"))
	var uuidKey, err9 = uuid.FromBytes(datastoreKey[:16])
	userlib.DatastoreSet(uuidKey, secureStoreEnc)
	if (err8 != nil) || (err9 != nil) {
		return nil, errors.New("Error5")
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var _, keyExists = userlib.KeystoreGet(username)

	//Error if no user exists for the given username
	if !keyExists {
		return nil, errors.New("no user exists for the given username")
	}

	//Get the HMAC/Encrypted secure struct from Datastore
	var salt = userlib.Hash([]byte(username))
	var rootKey = userlib.Argon2Key([]byte(password), salt, 16)

	var datastoreKey, err1 = userlib.HashKDF(rootKey, []byte("Secure User Struct Datastore Key"))
	var uuidDatastoreKey, err2 = uuid.FromBytes(datastoreKey[:16])
	var secureEnc, exists = userlib.DatastoreGet(uuidDatastoreKey)
	if (err1 != nil) || (err2 != nil) {
		return nil, errors.New("Error1")
	}

	//Error if the credentials are invalid
	if !exists {
		return nil, errors.New("Invalid credentials.")
	}

	// Decrypt the secure struct
	var secureStoreKey, err3 = userlib.HashKDF(rootKey, []byte("Secure User Struct Key"))
	var secureByte = userlib.SymDec(secureStoreKey[:16], secureEnc)

	// Get the secure struct
	var secure SecureStore
	var err4 = json.Unmarshal(secureByte, &secure)

	if (err3 != nil) || (err4 != nil) {
		return nil, errors.New("Error2")
	}

	// Check HMAC of ciphertext
	var hmacKey, err5 = userlib.HashKDF(rootKey, []byte("User Struct HMAC Key"))
	var checkHMAC, err6 = userlib.HMACEval(hmacKey[:16], secure.Ciphertext)
	var equal = userlib.HMACEqual(secure.HMAC, checkHMAC)
	if !equal {
		return nil, errors.New("Malicious activity detected.")
	}
	if (err5 != nil) || (err6 != nil) {
		return nil, errors.New("Error3")
	}

	//Decrypt and return the user pointer
	var encryptionKey, err7 = userlib.HashKDF(rootKey, []byte("User Struct"))
	var byteUserStruct = userlib.SymDec(encryptionKey[:16], secure.Ciphertext)
	var userStruct User
	var err8 = json.Unmarshal(byteUserStruct, &userStruct)
	userlib.DebugMsg("err7:", err7 != nil)
	userlib.DebugMsg("err8:", err8 != nil)
	if (err7 != nil) || (err8 != nil) {
		return nil, errors.New("Error4")
	}

	return &userStruct, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// Recreating the rootkey
	var salt = userlib.Hash([]byte(userdata.Username))
	var rootKey = userlib.Argon2Key([]byte(userdata.Password), salt, 16)

	// Creating the datastoreKey for the OWNER for the PLB
	var ogDsKey, ogDsKeyHashErr = userlib.HashKDF(rootKey, []byte("PLB"+filename))
	if ogDsKeyHashErr != nil {
		return errors.New("Error computing HashKDF")
	}
	var uuidOgDsKey, uuidOgDsErr = uuid.FromBytes(ogDsKey[:16])
	if uuidOgDsErr != nil {
		return errors.New("Error computing lookup key")
	}

	// Creating the datastoreKey for a SHARED user
	var shDsKey, shDsKeyHashErr = userlib.HashKDF(rootKey, []byte("PLBLLB"+filename))
	if shDsKeyHashErr != nil {
		return errors.New("Error computing HashKDF")
	}
	var uuidShDsKey, uuidShDsErr = uuid.FromBytes(shDsKey[:16])
	if uuidShDsErr != nil {
		return errors.New("Error computing lookup key")
	}

	// Check if the filename OR the lockbox (for shared users) exists in the namespace of the caller
	var ogLockboxByte, exists = userlib.DatastoreGet(uuidOgDsKey)
	var shLockboxByte, otherExists = userlib.DatastoreGet(uuidShDsKey)

	// If neither exists:
	if !exists && !otherExists {

		// Create a dummy file (will be put in NextPointer) to use for appends
		var dummyFile File
		var dummyFileBytes, dummyFileErr = json.Marshal(dummyFile)
		if dummyFileErr != nil {
			return errors.New("Err Marshaling dummyFile Store File")
		}

		// Create an encryption key
		var encryptionKey = userlib.RandomBytes(16)

		// Create a dummyFile encryption and HMAC keys
		var dfIV = userlib.RandomBytes(16)
		var dfHMACKey, dfHMACKeyErr = userlib.HashKDF(encryptionKey, []byte("File HMAC Key"))
		if dfHMACKeyErr != nil {
			return errors.New("Err computing Hash Store File")
		}

		// Create a secureStore for dummyFile AND encrypt dummyFile AND hmac dummyFile
		var dummyFileSecureStore SecureStore
		dummyFileSecureStore.Ciphertext = userlib.SymEnc(encryptionKey, dfIV, dummyFileBytes)
		var dummyFileSecureStoreHMAC, dummyFileSSHMACErr = userlib.HMACEval(dfHMACKey[:16], dummyFileSecureStore.Ciphertext)
		if dummyFileSSHMACErr != nil {
			return errors.New("Err Computing HMAC EVAL dummyFileSS Store File")
		}
		dummyFileSecureStore.HMAC = dummyFileSecureStoreHMAC

		// Put dummy secureStruct in datastore
		var dummyFileSecureStoreByte, dummyFiletempFileSecureStoreErr = json.Marshal(dummyFileSecureStore)
		if dummyFiletempFileSecureStoreErr != nil {
			return errors.New("Err Marshaling dummyFiletempFileSS Store File")
		}
		var dummyDSKey, dsError = userlib.HashKDF(rootKey, dummyFileSecureStoreByte)
		if dsError != nil {
			return errors.New("Err Computing Data Store Key for Dummy Struct")
		}
		var uuidDummyFileSecureStore, dummyFileSecureStoreDraftErr = uuid.FromBytes(dummyDSKey[:16])
		if dummyFileSecureStoreDraftErr != nil {
			return errors.New("Err Computing Draft Key dummyFileTempFileSS Store File")
		}
		userlib.DatastoreSet(uuidDummyFileSecureStore, dummyFileSecureStoreByte)

		// Create a the FIRST file (file that will contain content)
		var tempFile File

		// Create tempFile encryption key, HMAC key, and IV
		var tfIV = userlib.RandomBytes(16)
		var tfHMACKey, tfHMACKeyErr = userlib.HashKDF(encryptionKey, []byte("File HMAC Key"))
		if tfHMACKeyErr != nil {
			return errors.New("Err computing Hash Store File")
		}

		// Initialize tempFile
		tempFile.Text = content
		tempFile.NextPointer = uuidDummyFileSecureStore
		tempFile.TailPointer = uuidDummyFileSecureStore
		var tempFileBytes, tempFileBytesErr = json.Marshal(tempFile)
		if tempFileBytesErr != nil {
			return errors.New("Err Marshaling Temp File Store File")
		}

		// Create tempFile secureStore AND encrypt tempFile AND hmac tempFile
		var tempFileSecureStore SecureStore
		tempFileSecureStore.Ciphertext = userlib.SymEnc(encryptionKey, tfIV, tempFileBytes)
		var tempFileSecureStoreHMAC, tempFileSecureStoreHMACErr = userlib.HMACEval(tfHMACKey[:16], tempFileSecureStore.Ciphertext)
		if tempFileSecureStoreHMACErr != nil {
			return errors.New("Err HMAC Evaling tempFileSS Store File")
		}
		tempFileSecureStore.HMAC = tempFileSecureStoreHMAC

		// Put tempFile secureStruct into datastore
		var tempFileSecureStoreByte, tempFiletempFileSecureStoreErr = json.Marshal(tempFileSecureStore)
		if tempFiletempFileSecureStoreErr != nil {
			return errors.New("Err Marshalling tempFileSS Store File")
		}
		var tempDSKey, tdsError = userlib.HashKDF(rootKey, tempFileSecureStoreByte)
		if tdsError != nil {
			return errors.New("Err Computing Data Store Key for Dummy Struct")
		}
		var uuidTempFileSecureStore, tempFileSecureStoreDraftErr = uuid.FromBytes(tempDSKey[:16])
		if tempFileSecureStoreDraftErr != nil {
			return errors.New("Err Computing Draft Key tempFileSS Store File")
		}
		userlib.DatastoreSet(uuidTempFileSecureStore, tempFileSecureStoreByte)

		// Create the PLB and initialize
		var ogFileLockBox PersonalLockbox
		ogFileLockBox.DecryptionKey = encryptionKey
		ogFileLockBox.FileOrLockBoxPointer = uuidTempFileSecureStore

		// Create the PLB encryption key
		var lockboxEncryptionKey, lockboxEncryptionKeyErr = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
		if lockboxEncryptionKeyErr != nil {
			return errors.New("Err Computing Hash lbEncKey Store File")
		}

		// Encrypt the PLB
		var ogFileLockBoxByte, ogFileLockBoxByteErr = json.Marshal(ogFileLockBox)
		if ogFileLockBoxByteErr != nil {
			return errors.New("Err Marshaling ogFileLockBox Store File")
		}
		var lockedPLB = userlib.SymEnc(lockboxEncryptionKey[:16], userlib.RandomBytes(16), ogFileLockBoxByte)

		// // Set the PLB in Datastore
		// var ogFileLockBoxLookupKDF, ogFileLockBoxLookupKDFErr = userlib.HashKDF(rootKey, []byte("PLB"+filename))
		// if ogFileLockBoxLookupKDFErr != nil {
		// 	return errors.New("Err Hashing ogFileLockBox Store File")
		// }
		// var uuidOgFileLockBox, ogFileLockBoxFinalDraftErr = uuid.FromBytes(ogFileLockBoxLookupKDF[:16])
		// if ogFileLockBoxFinalDraftErr != nil {
		// 	return errors.New("Err Hashing ogFileLockBox Final Draft Err")
		// }

		// Set the PLB in Datastore
		userlib.DatastoreSet(uuidOgDsKey, lockedPLB)

	} else { //If the file exists

		var ownerLockbox PersonalLockbox

		if exists { // OWNER CASE

			// Get decryption key for PLB and decrypt
			var decryptionKey, decryptionKeyErr = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
			if decryptionKeyErr != nil {
				return errors.New("Err Hashing PLB Err")
			}
			var unlockedPLB = userlib.SymDec(decryptionKey[:16], ogLockboxByte)
			json.Unmarshal(unlockedPLB, &ownerLockbox)

			// Get the securStore struct from PLB
			var ogFileSS SecureStore
			var secureStoreByte, SecureStoreByteErr = userlib.DatastoreGet(ownerLockbox.FileOrLockBoxPointer)
			if SecureStoreByteErr != true {
				return errors.New("Err Getting PLB Err")
			}
			json.Unmarshal(secureStoreByte, &ogFileSS)

			// Verify HMAC on ciphertext inside secureStruct
			var tfHMACKey, tfHMACKeyErr = userlib.HashKDF(ownerLockbox.DecryptionKey[:16], []byte("File HMAC Key"))
			if tfHMACKeyErr != nil {
				return errors.New("Err computing Hash Store File")
			}
			var ogFileSSHMAC, HMACErr = userlib.HMACEval(tfHMACKey[:16], ogFileSS.Ciphertext)
			if HMACErr != nil {
				return errors.New("Err computing HMAC OgFileSS Err")
			}
			var verifyHMAC = userlib.HMACEqual(ogFileSS.HMAC, ogFileSSHMAC)
			if !verifyHMAC {
				return errors.New("File has been tampered with")
			}

			// Get the file inside the secureStruct AND decrypt AND overwrite with new content
			var ogFileItself File
			json.Unmarshal(userlib.SymDec(ownerLockbox.DecryptionKey[:16], ogFileSS.Ciphertext), &ogFileItself)
			ogFileItself.Text = content

			// Create a dummy file (will be put in NextPointer) to use for appends
			var dummyFile File
			var dummyFileBytes, dummyFileErr = json.Marshal(dummyFile)
			if dummyFileErr != nil {
				return errors.New("Err Marshaling dummyFile Store File")
			}

			// Create an encryption key
			var encryptionKey = ownerLockbox.DecryptionKey[:16]

			// Create a dummyFile encryption and HMAC keys
			var dfIV = userlib.RandomBytes(16)
			var dfHMACKey, dfHMACKeyErr = userlib.HashKDF(ownerLockbox.DecryptionKey[:16], []byte("File HMAC Key"))
			if dfHMACKeyErr != nil {
				return errors.New("Err computing Hash Store File")
			}

			// Create a secureStore for dummyFile AND encrypt dummyFile AND hmac dummyFile
			var dummyFileSecureStore SecureStore
			dummyFileSecureStore.Ciphertext = userlib.SymEnc(encryptionKey, dfIV, dummyFileBytes)
			var dummyFileSecureStoreHMAC, dummyFileSSHMACErr = userlib.HMACEval(dfHMACKey[:16], dummyFileSecureStore.Ciphertext)
			if dummyFileSSHMACErr != nil {
				return errors.New("Err Computing HMAC EVAL dummyFileSS Store File")
			}
			dummyFileSecureStore.HMAC = dummyFileSecureStoreHMAC

			// Put dummy secureStruct in datastore
			var dummyFileSecureStoreByte, dummyFiletempFileSecureStoreErr = json.Marshal(dummyFileSecureStore)
			if dummyFiletempFileSecureStoreErr != nil {
				return errors.New("Err Marshaling dummyFiletempFileSS Store File")
			}
			var dummyDSKey, dsError = userlib.HashKDF(rootKey, dummyFileSecureStoreByte)
			if dsError != nil {
				return errors.New("Err Computing Data Store Key for Dummy Struct")
			}
			var uuidDummyFileSecureStore, dummyFileSecureStoreDraftErr = uuid.FromBytes(dummyDSKey[:16])
			if dummyFileSecureStoreDraftErr != nil {
				return errors.New("Err Computing Draft Key dummyFileTempFileSS Store File")
			}
			userlib.DatastoreSet(uuidDummyFileSecureStore, dummyFileSecureStoreByte)

			//have the newOgFile next point to dummy
			ogFileItself.NextPointer = uuidDummyFileSecureStore
			ogFileItself.TailPointer = uuidDummyFileSecureStore

			// Re-encrypt the file and set in ogFileSS
			var overwriteByte, overwriteByteErr = json.Marshal(ogFileItself)
			if overwriteByteErr != nil {
				return errors.New("Err computing HMAC OgFileSS Err")
			}
			ogFileSS.Ciphertext = userlib.SymEnc(ownerLockbox.DecryptionKey[:16], userlib.RandomBytes(16), overwriteByte)

			// Re-evaluate HMAC and set in ogFileSS
			var ogFileSSHMAC2, ogFileSSHMACErr = userlib.HMACEval(tfHMACKey[:16], ogFileSS.Ciphertext)
			if ogFileSSHMACErr != nil {
				return errors.New("Err computing HMAC OgFileSS Err")
			}
			ogFileSS.HMAC = ogFileSSHMAC2

			// Put secureStruct back into DataStore
			var secureByte, _ = json.Marshal(ogFileSS)
			userlib.DatastoreSet(ownerLockbox.FileOrLockBoxPointer, secureByte)

		} else { // SHARED USER CASE

			var ownerLockbox PersonalLockbox

			// Get decryption key for PLB and decrypt
			if otherExists {
				var decryptionKey, decryptionKeyErr = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
				if decryptionKeyErr != nil {
					return errors.New("Err Hashing PLB Err")
				}
				var unlockedPLB = userlib.SymDec(decryptionKey[:16], shLockboxByte)
				json.Unmarshal(unlockedPLB, &ownerLockbox)

				// Get the FLB from the PLB
				var FLBEnc, FLBEncErr = userlib.DatastoreGet(ownerLockbox.FileOrLockBoxPointer)
				if FLBEncErr != true {
					return errors.New("Err Hashing PLB Err")
				}

				// Decrypt FLB
				var FLB Lockbox
				var unlockedFLB = userlib.SymDec(ownerLockbox.DecryptionKey[:16], FLBEnc)
				json.Unmarshal(unlockedFLB, &FLB)

				// Get the secureStruct from the PLB
				var secureStoreByte, SecureStoreByteErr = userlib.DatastoreGet(FLB.EncFile)
				if SecureStoreByteErr != true {
					errors.New("Err Getting PLB Err")
				}
				var ogFileSS SecureStore
				json.Unmarshal(secureStoreByte, &ogFileSS)

				// Verify HMAC on ciphertext inside secureStruct
				var tfHMACKey, tfHMACKeyErr = userlib.HashKDF(FLB.DecryptionKey, []byte("File HMAC Key"))
				if tfHMACKeyErr != nil {
					return errors.New("Err computing Hash Store File")
				}
				var ogFileSSHMAC, HMACErr = userlib.HMACEval(tfHMACKey[:16], ogFileSS.Ciphertext)
				if HMACErr != nil {
					errors.New("Err computing HMAC OgFileSS Err")
				}
				var verifyHMAC2 = userlib.HMACEqual(ogFileSS.HMAC, ogFileSSHMAC)
				if !verifyHMAC2 {
					return errors.New("File has been tampered with")
				}

				// Get the file inside the secureStruct AND decrypt AND overwrite with new content
				var ogFileItself File
				json.Unmarshal(userlib.SymDec(FLB.DecryptionKey[:16], ogFileSS.Ciphertext), &ogFileItself)
				ogFileItself.Text = content

				// Create a dummy file (will be put in NextPointer) to use for appends
				var dummyFile File
				var dummyFileBytes, dummyFileErr = json.Marshal(dummyFile)
				if dummyFileErr != nil {
					return errors.New("Err Marshaling dummyFile Store File")
				}

				// Create an encryption key
				var encryptionKey = ownerLockbox.DecryptionKey[:16]

				// Create a dummyFile encryption and HMAC keys
				var dfIV = userlib.RandomBytes(16)
				var dfHMACKey, dfHMACKeyErr = userlib.HashKDF(FLB.DecryptionKey[:16], []byte("File HMAC Key"))
				if dfHMACKeyErr != nil {
					return errors.New("Err computing Hash Store File")
				}

				// Create a secureStore for dummyFile AND encrypt dummyFile AND hmac dummyFile
				var dummyFileSecureStore SecureStore
				dummyFileSecureStore.Ciphertext = userlib.SymEnc(encryptionKey, dfIV, dummyFileBytes)
				var dummyFileSecureStoreHMAC, dummyFileSSHMACErr = userlib.HMACEval(dfHMACKey[:16], dummyFileSecureStore.Ciphertext)
				if dummyFileSSHMACErr != nil {
					return errors.New("Err Computing HMAC EVAL dummyFileSS Store File")
				}
				dummyFileSecureStore.HMAC = dummyFileSecureStoreHMAC

				// Put dummy secureStruct in datastore
				var dummyFileSecureStoreByte, dummyFiletempFileSecureStoreErr = json.Marshal(dummyFileSecureStore)
				if dummyFiletempFileSecureStoreErr != nil {
					return errors.New("Err Marshaling dummyFiletempFileSS Store File")
				}
				var dummyDSKey, dsError = userlib.HashKDF(rootKey, dummyFileSecureStoreByte)
				if dsError != nil {
					return errors.New("Err Computing Data Store Key for Dummy Struct")
				}
				var uuidDummyFileSecureStore, dummyFileSecureStoreDraftErr = uuid.FromBytes(dummyDSKey[:16])
				if dummyFileSecureStoreDraftErr != nil {
					return errors.New("Err Computing Draft Key dummyFileTempFileSS Store File")
				}
				userlib.DatastoreSet(uuidDummyFileSecureStore, dummyFileSecureStoreByte)

				//have the newOgFile next point to dummy
				ogFileItself.NextPointer = uuidDummyFileSecureStore
				ogFileItself.TailPointer = uuidDummyFileSecureStore

				// Re-encrypt the file and set in ogFileSS
				var overwriteByte, overwriteByteErr = json.Marshal(ogFileItself)
				if overwriteByteErr != nil {
					return errors.New("Err computing HMAC OgFileSS Err")
				}
				ogFileSS.Ciphertext = userlib.SymEnc(FLB.DecryptionKey[:16], userlib.RandomBytes(16), overwriteByte)

				// Re-evaluate HMAC and set in ogFileSS
				var ogFileSSHMAC2, ogFileSSHMACErr = userlib.HMACEval(tfHMACKey[:16], ogFileSS.Ciphertext)
				if ogFileSSHMACErr != nil {
					return errors.New("Err computing HMAC OgFileSS Err")
				}
				ogFileSS.HMAC = ogFileSSHMAC2

				// Put secureStruct back into DataStore
				var secureByte, _ = json.Marshal(ogFileSS)
				userlib.DatastoreSet(FLB.EncFile, secureByte)
			}
		}
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	// Recreate the rootKey
	var salt = userlib.Hash([]byte(userdata.Username))
	var rootKey = userlib.Argon2Key([]byte(userdata.Password), salt, 16)

	// Creating the datastoreKey for the filename (check if ORIGINAL owner)
	var ogDsKey, ogDsKeyHashErr = userlib.HashKDF(rootKey, []byte("PLB"+filename))
	if ogDsKeyHashErr != nil {
		return errors.New("Error computing HashKDF")
	}
	var uuidOgDsKey, uuidOgDsErr = uuid.FromBytes(ogDsKey[:16])
	if uuidOgDsErr != nil {
		return errors.New("Error computing lookup key")
	}
	var ogLockboxByte, exists = userlib.DatastoreGet(uuidOgDsKey)

	// Creating the datastoreKey for the filename (check if SHARED)
	var shDsKey, shDsKeyHashErr = userlib.HashKDF(rootKey, []byte("PLBLLB"+filename))
	if shDsKeyHashErr != nil {
		return errors.New("Error computing HashKDF")
	}
	var uuidShDsKey, uuidShDsErr = uuid.FromBytes(shDsKey[:16])
	if uuidShDsErr != nil {
		return errors.New("Error computing lookup key")
	}
	var shLockboxByte, otherExists = userlib.DatastoreGet(uuidShDsKey)

	if !exists && !otherExists {
		return errors.New(strings.ToTitle("file not found"))
	} else {

		//if exists get the lockbox
		var ownerLockbox PersonalLockbox
		if exists {

			// Decrypt PLB
			var decryptionKey, dcKeyErr = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
			if dcKeyErr != nil {
				return errors.New("Error hashKDF PLB")
			}
			var unlockedLB = userlib.SymDec(decryptionKey[:16], ogLockboxByte)
			json.Unmarshal(unlockedLB, &ownerLockbox)

			// Read the lockbox for secure store details
			var ogFSecStrByte, ogFileSecStrErr = userlib.DatastoreGet(ownerLockbox.FileOrLockBoxPointer)
			if ogFileSecStrErr != true {
				return errors.New("No file exists at UUID for the ogFileSS Line 619")
			}
			var ogFileSecureStore SecureStore
			json.Unmarshal(ogFSecStrByte, &ogFileSecureStore)

			/*verify the file HMAC
			var ogFileHMAC, ogFileHMACErr = userlib.HMACEval(rootKey, ogFileSecureStore.Ciphertext)
			if ogFileHMACErr != nil {
				return errors.New("Error computing ogFile HMAC")
			}
			var verifyOGHMAC = userlib.HMACEqual(ogFileSecureStore.HMAC, ogFileHMAC)

			if !verifyOGHMAC {
				return errors.New("OG File Tamper")
			}*/

			// Get file details
			var ogFileBytes = userlib.SymDec(ownerLockbox.DecryptionKey[:16], ogFileSecureStore.Ciphertext)
			var ogFileItself File
			json.Unmarshal(ogFileBytes, &ogFileItself)

			// Get the file at the tail
			var tailFileSSBytes, tailFileGetErr = userlib.DatastoreGet(ogFileItself.TailPointer)
			if tailFileGetErr != true {
				return errors.New("No file exists at Tail File lookup key")
			}
			var tailFileSecureStore SecureStore
			json.Unmarshal(tailFileSSBytes, &tailFileSecureStore)

			// Verify tail HMAC
			var tailHMACKey, tailHMACKeyError = userlib.HashKDF(ownerLockbox.DecryptionKey[:16], []byte("File HMAC Key"))
			if tailHMACKeyError != nil {
				return errors.New("Error computing tail file HMAC Key")
			}
			var tailFileHMAC, tailHMACErr = userlib.HMACEval(tailHMACKey[:16], tailFileSecureStore.Ciphertext)
			if tailHMACErr != nil {
				return errors.New("Error computing tail file HMAC")
			}
			var verifyTailHMAC = userlib.HMACEqual(tailFileSecureStore.HMAC, tailFileHMAC)
			if !verifyTailHMAC {
				return errors.New("Tail File Tamper")
			}

			// Get the tail file
			var tailFile File
			json.Unmarshal(userlib.SymDec(ownerLockbox.DecryptionKey, tailFileSecureStore.Ciphertext), &tailFile)

			// Write content into the tail file
			tailFile.Text = content

			// Create new tail file
			var tempNextDummyFile File

			// Create new tail file secureStruct
			var newSecureStore SecureStore

			// Encrypt the new tail and store it in secureStore
			var tempNextDummyFileByte, dumFileByteErr = json.Marshal(tempNextDummyFile)
			if dumFileByteErr != nil {
				return errors.New("Error marshalling Tail File")
			}
			var newTailEnc = userlib.SymEnc(ownerLockbox.DecryptionKey[:16], userlib.RandomBytes(16), tempNextDummyFileByte)
			newSecureStore.Ciphertext = newTailEnc

			// Create HMAC for new tail file and set in secureStore
			var newHMAC, error1 = userlib.HMACEval(tailHMACKey[:16], newSecureStore.Ciphertext)
			if error1 != nil {
				return errors.New("Error computing tail file HMAC")
			}
			newSecureStore.HMAC = newHMAC

			// Store the new file secure struct into datastore
			var newDatastoreData, _ = json.Marshal(newSecureStore)
			var newDataStoreKey, dumFileHashErr = userlib.HashKDF(rootKey, tempNextDummyFileByte)
			if dumFileHashErr != nil {
				return errors.New("Error Computing Hash of Tail File")
			}
			var newUUID, dumFileFinalDraftErr = uuid.FromBytes(newDataStoreKey[:16])
			if dumFileFinalDraftErr != nil {
				return errors.New("Error computing Final Draft Tail File")
			}
			userlib.DatastoreSet(newUUID, newDatastoreData)

			// Have old tail file point to new tail file
			tailFile.NextPointer = newUUID

			// Encrypt the old tail and store it its secureStore
			var tailByte, error4 = json.Marshal(tailFile)
			if error4 != nil {
				return errors.New("Error marshalling")
			}
			var tailEnc = userlib.SymEnc(ownerLockbox.DecryptionKey[:16], userlib.RandomBytes(16), tailByte)
			tailFileSecureStore.Ciphertext = tailEnc

			// Update old tail HMAC
			var tailHMAC, error3 = userlib.HMACEval(tailHMACKey[:16], tailFileSecureStore.Ciphertext)
			if error3 != nil {
				return errors.New("Error computing tail file HMAC")
			}
			tailFileSecureStore.HMAC = tailHMAC

			// Store back tail secure store back in datastore
			var tailData, _ = json.Marshal(tailFileSecureStore)
			userlib.DatastoreSet(ogFileItself.TailPointer, tailData)

			// Have the ogFile Tail point to it.
			ogFileItself.TailPointer = newUUID

			// Encrypt the head file and store it its secureStore
			var headByte, error5 = json.Marshal(ogFileItself)
			if error5 != nil {
				return errors.New("Error marshalling")
			}
			var headEnc = userlib.SymEnc(ownerLockbox.DecryptionKey[:16], userlib.RandomBytes(16), headByte)
			ogFileSecureStore.Ciphertext = headEnc

			// Update old tail HMAC
			var headHMAC, error6 = userlib.HMACEval(tailHMACKey[:16], ogFileSecureStore.Ciphertext)
			if error6 != nil {
				return errors.New("Error computing tail file HMAC")
			}
			ogFileSecureStore.HMAC = headHMAC

			// Store back tail secure store back in datastore
			var headData, _ = json.Marshal(ogFileSecureStore)
			userlib.DatastoreSet(ownerLockbox.FileOrLockBoxPointer, headData)

		} else if otherExists {
			var PLBLLB PersonalLockbox
			if otherExists {

				var decryptionKey, dcKeyErr = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
				if dcKeyErr != nil {
					return errors.New("Error hashKDF PLB")
				}
				var unlockedPLB = userlib.SymDec(decryptionKey[:16], shLockboxByte)
				json.Unmarshal(unlockedPLB, &PLBLLB)

				//read the lockbox for file lockbox details
				var LLBByte, LLBByteErr = userlib.DatastoreGet(PLBLLB.FileOrLockBoxPointer)
				if LLBByteErr != true {
					return errors.New("Error getting the LLB from Datastore UUID")
				}

				//Decrypt LLB
				var unlockedLLB = userlib.SymDec(PLBLLB.DecryptionKey[:16], LLBByte)

				//LLB
				var LLB Lockbox
				json.Unmarshal(unlockedLLB, &LLB)

				//get the OG File SS
				var ogFileSSBytes, ogFileSSBytesErr = userlib.DatastoreGet(LLB.EncFile)
				if ogFileSSBytesErr != true {
					return errors.New("Error getting OG File in DataStore Shared User")
				}

				// OG File SS
				var ogFileSS SecureStore
				json.Unmarshal(ogFileSSBytes, &ogFileSS)

				//verify the file HMAC
				/*var ogFileHMAC, ogFileHMACErr = userlib.HMACEval(rootKey, ogFileSS.Ciphertext)
				if ogFileHMACErr != nil {
					return errors.New("Error computing ogFile HMAC")
				}
				var verifyOGHMAC = userlib.HMACEqual(ogFileSS.HMAC, ogFileHMAC)

				if !verifyOGHMAC {
					errors.New("OG File Tamper shared user")
				}*/

				//read the lockbox for file details
				var ogFileBytes = userlib.SymDec(LLB.DecryptionKey[:16], ogFileSS.Ciphertext)
				var ogFileItself File
				json.Unmarshal(ogFileBytes, &ogFileItself)

				//get the file at the tail
				var tailFileSSBytes, tailFileGetErr = userlib.DatastoreGet(ogFileItself.TailPointer)
				if tailFileGetErr != true {
					return errors.New("No file exists at Tail File lookup key")
				}
				var tailFileSS SecureStore
				json.Unmarshal(tailFileSSBytes, &tailFileSS)

				// //verify the tail Pointer HMAC
				var tailHMACKey2, _ = userlib.HashKDF(LLB.DecryptionKey[:16], []byte("File HMAC Key"))
				// if tailHMACKeyError2 != nil {
				// 	return errors.New("Error computing tail file HMAC Key")
				// }
				// var tailFileHMACEval, tailFileHMACEvalErr = userlib.HMACEval(tailHMACKey2[:16], ogFileItself.Text)
				// if tailFileHMACEvalErr != nil {
				// 	return errors.New("Error computing tail file HMAC Shared User")
				// }
				// var verifyTailHMAC = userlib.HMACEqual(tailFileSS.HMAC, tailFileHMACEval)
				// if !verifyTailHMAC {
				// 	errors.New("Tail File Tamper Shared user")
				// }

				//tail file
				var tailFile File
				json.Unmarshal(userlib.SymDec(LLB.DecryptionKey[:16], tailFileSS.Ciphertext), &tailFile)

				//write in the tail file
				tailFile.Text = content

				// Create new tail file
				var tempNextDummyFile File

				// Create new tail file secureStruct
				var newSecureStore SecureStore

				// Encrypt the new tail and store it in secureStore
				var tempNextDummyFileByte, dumFileByteErr = json.Marshal(tempNextDummyFile)
				if dumFileByteErr != nil {
					return errors.New("Error marshalling Tail File")
				}
				var newTailEnc = userlib.SymEnc(LLB.DecryptionKey[:16], userlib.RandomBytes(16), tempNextDummyFileByte)
				newSecureStore.Ciphertext = newTailEnc

				// Create HMAC for new tail file and set in secureStore
				var newHMAC, error1 = userlib.HMACEval(tailHMACKey2[:16], newSecureStore.Ciphertext)
				if error1 != nil {
					return errors.New("Error computing tail file HMAC")
				}
				newSecureStore.HMAC = newHMAC

				// Store the secure struct into datastore
				var newDatastoreData, _ = json.Marshal(newSecureStore)
				var newDataStoreKey, dumFileHashErr = userlib.HashKDF(rootKey, tempNextDummyFileByte)
				if dumFileHashErr != nil {
					return errors.New("Error Computing Hash of Tail File")
				}
				var newUUID, dumFileFinalDraftErr = uuid.FromBytes(newDataStoreKey[:16])
				if dumFileFinalDraftErr != nil {
					return errors.New("Error computing Final Draft Tail File")
				}
				userlib.DatastoreSet(newUUID, newDatastoreData)

				// Have old tail file point to new tail file
				tailFile.NextPointer = newUUID

				// Encrypt the old tail and store it its secureStore
				var tailByte, error4 = json.Marshal(tailFile)
				if error4 != nil {
					return errors.New("Error marshalling")
				}
				var tailEnc = userlib.SymEnc(LLB.DecryptionKey[:16], userlib.RandomBytes(16), tailByte)
				tailFileSS.Ciphertext = tailEnc

				// Update old tail HMAC
				var tailHMAC, error3 = userlib.HMACEval(tailHMACKey2[:16], tailFileSS.Ciphertext)
				if error3 != nil {
					return errors.New("Error computing tail file HMAC")
				}
				tailFileSS.HMAC = tailHMAC

				// Store back tail secure store back in datastore
				var tailData, _ = json.Marshal(tailFileSS)
				userlib.DatastoreSet(ogFileItself.TailPointer, tailData)

				// Have the ogFile Tail point to it.
				ogFileItself.TailPointer = newUUID

				// Encrypt the head file and store it its secureStore
				var headByte, error5 = json.Marshal(ogFileItself)
				if error5 != nil {
					return errors.New("Error marshalling")
				}
				var headEnc = userlib.SymEnc(LLB.DecryptionKey[:16], userlib.RandomBytes(16), headByte)
				ogFileSS.Ciphertext = headEnc

				// Update old tail HMAC
				var headHMAC, error6 = userlib.HMACEval(tailHMACKey2[:16], ogFileSS.Ciphertext)
				if error6 != nil {
					return errors.New("Error computing tail file HMAC")
				}
				ogFileSS.HMAC = headHMAC

				// Store back head secure store back in datastore
				var headData, _ = json.Marshal(ogFileSS)
				userlib.DatastoreSet(LLB.EncFile, headData)

			}
		}
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	// Recreate the rootKey
	var salt = userlib.Hash([]byte(userdata.Username))
	var rootKey = userlib.Argon2Key([]byte(userdata.Password), salt, 16)

	// Creating the datastoreKey for the OWNER for the PLB
	var ogDsKey, ogDsKeyHashErr = userlib.HashKDF(rootKey, []byte("PLB"+filename))
	if ogDsKeyHashErr != nil {
		return nil, errors.New("Error computing HashKDF")
	}
	var uuidOgDsKey, uuidOgDsErr = uuid.FromBytes(ogDsKey[:16])
	if uuidOgDsErr != nil {
		return nil, errors.New("Error computing lookup key")
	}

	// Creating the datastoreKey for a SHARED user
	var shDsKey, shDsKeyHashErr = userlib.HashKDF(rootKey, []byte("PLBLLB"+filename))
	if shDsKeyHashErr != nil {
		return nil, errors.New("Error computing HashKDF")
	}
	var uuidShDsKey, uuidShDsErr = uuid.FromBytes(shDsKey[:16])
	if uuidShDsErr != nil {
		return nil, errors.New("Error computing lookup key")
	}

	// Check if the filename OR the lockbox (for shared users) exists in the namespace of the caller
	var ogLockboxByte, exists = userlib.DatastoreGet(uuidOgDsKey)
	var shLockboxByte, otherExists = userlib.DatastoreGet(uuidShDsKey)

	// If neither exists:
	if !exists && !otherExists {
		return nil, errors.New(strings.ToTitle("file not found"))
	} else {

		var ownerLockbox PersonalLockbox

		if exists { // OWNER CASE

			// Get decryption key for PLB and decrypt
			var decryptionKey, dcKeyErr = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
			if dcKeyErr != nil {
				return nil, errors.New("Error hashKDF PLB")
			}
			var unlockedLB = userlib.SymDec(decryptionKey[:16], ogLockboxByte)
			json.Unmarshal(unlockedLB, &ownerLockbox)

			// Get the secureStore struct from the PLB
			var ogFileSecureStore SecureStore
			var ogFSecStrByte, ogFileSecStrErr = userlib.DatastoreGet(ownerLockbox.FileOrLockBoxPointer)
			if ogFileSecStrErr != true {
				return nil, errors.New("No file exists at UUID for the ogFileSS")
			}
			json.Unmarshal(ogFSecStrByte, &ogFileSecureStore)

			//Verify HMAC on ciphertext inside secureStruct
			var tfHMACKey, tfHMACKeyErr = userlib.HashKDF(ownerLockbox.DecryptionKey, []byte("File HMAC Key"))
			if tfHMACKeyErr != nil {
				return nil, errors.New("Error")
			}

			var ogFileHMAC, ogFileHMACErr = userlib.HMACEval(tfHMACKey[:16], ogFileSecureStore.Ciphertext)
			if ogFileHMACErr != nil {
				return nil, errors.New("Error computing ogFile HMAC")
			}
			var verifyOGHMAC = userlib.HMACEqual(ogFileSecureStore.HMAC, ogFileHMAC)
			if !verifyOGHMAC {
				return nil, errors.New("OG File Taaaaaamper12")
			}

			// Decrypt the file struct
			var ogFileItself File
			var ogFileBytes = userlib.SymDec(ownerLockbox.DecryptionKey[:16], ogFileSecureStore.Ciphertext)
			json.Unmarshal(ogFileBytes, &ogFileItself)

			// Get the tail of the file
			var tailFileSecureStore SecureStore
			var tailFileSSBytes, tailFileGetErr = userlib.DatastoreGet(ogFileItself.TailPointer)
			if tailFileGetErr != true {
				return nil, errors.New("No file exists at Tail File lookup key")
			}
			json.Unmarshal(tailFileSSBytes, &tailFileSecureStore)

			// Get the tail file
			var tailFile File
			json.Unmarshal(userlib.SymDec(ownerLockbox.DecryptionKey[:16], tailFileSecureStore.Ciphertext), tailFile)

			// Get a new file
			var newFileByte []byte
			var newFileSS SecureStore
			var newFile = ogFileItself
			var newContent = ogFileItself.Text
			if newFile.NextPointer != ogFileItself.NextPointer {
			}
			for i := 0; i < 10000; i++ {
				fmt.Printf("starting iteration %d\n", i)

				// If the end of the file has been reached
				if newFile.NextPointer == ogFileItself.TailPointer {
					if i == 0 {
						break
					} else {
						var newFileSSByte, newFileByteSSErr = userlib.DatastoreGet(newFile.NextPointer)
						if newFileByteSSErr != true {
							return nil, errors.New("Error finding next file efficient Append")
						}
						json.Unmarshal(newFileSSByte, &newFileSS)
						newFileByte = userlib.SymDec(ownerLockbox.DecryptionKey[:16], newFileSS.Ciphertext)
						json.Unmarshal(newFileByte, &newFile)
						newContent = append(newContent, newFile.Text...)
						fmt.Printf("new content is %s\n", newContent)
						break
					}
				}
				// Get the next file
				var newFileSSByte, newFileByteSSErr = userlib.DatastoreGet(newFile.NextPointer)
				if newFileByteSSErr != true {
					return nil, errors.New("Error finding next file efficient Append")
				}
				json.Unmarshal(newFileSSByte, &newFileSS)
				newFileByte = userlib.SymDec(ownerLockbox.DecryptionKey[:16], newFileSS.Ciphertext)
				json.Unmarshal(newFileByte, &newFile)

				// Append new content
				newContent = append(newContent, newFile.Text...)
				fmt.Printf("new content is %s\n", newContent)
			}

			// Condense all appends into the header file
			ogFileItself.Text = newContent
			ogFileItself.NextPointer = ogFileItself.TailPointer

			// Encrypt new file and get HMAC and write both back into secureStruct
			var overwriteByte, overwriteByteErr = json.Marshal(ogFileItself)
			if overwriteByteErr != nil {
				return nil, errors.New("Err computing HMAC OgFileSS Err")
			}
			ogFileSecureStore.Ciphertext = userlib.SymEnc(ownerLockbox.DecryptionKey[:16], userlib.RandomBytes(16), overwriteByte)

			// Verify HMAC on ciphertext inside secureStruct
			var tfHMACKey2, tfHMACKeyErr2 = userlib.HashKDF(ownerLockbox.DecryptionKey[:16], []byte("File HMAC Key"))
			if tfHMACKeyErr2 != nil {
				return nil, errors.New("Err computing Hash Store File")
			}
			var ogFileSSHMAC2, HMACErr2 = userlib.HMACEval(tfHMACKey2[:16], ogFileSecureStore.Ciphertext)
			if HMACErr2 != nil {
				return nil, errors.New("Err computing HMAC OgFileSS Err")
			}

			// var ogFileSSHMAC2, ogFileSSHMACErr = userlib.HMACEval(ownerLockbox.DecryptionKey[:16], ogFileSecureStore.Ciphertext)
			// if ogFileSSHMACErr != nil {
			// 	return nil, errors.New("Err computing HMAC OgFileSS Err")
			// }
			ogFileSecureStore.HMAC = ogFileSSHMAC2

			// Store securestruct back in datastore
			var secureByte, secureError = json.Marshal(ogFileSecureStore)
			if secureError != nil {
				return nil, errors.New("Error marshaling secure struct")
			}
			userlib.DatastoreSet(ownerLockbox.FileOrLockBoxPointer, secureByte)

			return newContent, nil

		} else if otherExists {

			var PLBLLB PersonalLockbox

			// Get decryption key for PLB and decrypt
			var decryptionKey, dcKeyErr = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
			if dcKeyErr != nil {
				return nil, errors.New("Error hashKDF PLB")
			}
			var unlockedPLB = userlib.SymDec(decryptionKey[:16], shLockboxByte)
			json.Unmarshal(unlockedPLB, &PLBLLB)

			// Get the encrypted LLB
			var LLBByte, LLBByteErr = userlib.DatastoreGet(PLBLLB.FileOrLockBoxPointer)
			if !LLBByteErr {
				return nil, errors.New("Error getting the LLB from Datastore UUID")
			}

			// Get LLB Decrypt Key
			// var decryptionKeyLLB, dcKeyLLBErr = userlib.HashKDF(rootKey, []byte("LLB ENC Key"+filename))
			// if dcKeyLLBErr != nil {
			// 	return nil, errors.New("Error hashKDF LLB Enc Key")
			// }

			// Decrypt LLB
			var unlockedLLB = userlib.SymDec(PLBLLB.DecryptionKey[:16], LLBByte)

			// Get LLB (physical object)
			var LLB Lockbox
			json.Unmarshal(unlockedLLB, &LLB)

			// Get the OG File SS
			var ogFileSSBytes, ogFileSSBytesErr = userlib.DatastoreGet(LLB.EncFile)
			if ogFileSSBytesErr != true {
				return nil, errors.New("Error getting OG File in DataStore Shared User")
			}

			// OG File SS
			var ogFileSS SecureStore
			json.Unmarshal(ogFileSSBytes, &ogFileSS)

			// Verify the file HMAC
			var fileHMACKey, fileHMACKeyErr = userlib.HashKDF(LLB.DecryptionKey, []byte("File HMAC Key"))
			if fileHMACKeyErr != nil {
				return nil, errors.New("Error with file HMAC key gen")
			}
			var ogFileHMAC, ogFileHMACErr = userlib.HMACEval(fileHMACKey[:16], ogFileSS.Ciphertext)
			if ogFileHMACErr != nil {
				return nil, errors.New("Error computing ogFile HMAC")
			}
			var verifyOGHMAC = userlib.HMACEqual(ogFileSS.HMAC, ogFileHMAC)
			if !verifyOGHMAC {
				return nil, errors.New("OG File Tamper shared user")
			}

			// Read the secureStruct for file details
			var ogFileBytes = userlib.SymDec(LLB.DecryptionKey[:16], ogFileSS.Ciphertext)
			var ogFileItself File
			json.Unmarshal(ogFileBytes, &ogFileItself)

			// Get the file at the tail
			var tailFileSS SecureStore
			var tailFileSSBytes, tailFileGetErr = userlib.DatastoreGet(ogFileItself.TailPointer)
			if tailFileGetErr != true {
				return nil, errors.New("No file exists at Tail File lookup key")
			}
			json.Unmarshal(tailFileSSBytes, &tailFileSS)

			// Verify the tail Pointer HMAC
			// var tailHMACKey, tailHMACKeyErr = userlib.HashKDF(LLB.DecryptionKey, []byte("File HMAC Key"))
			// if tailHMACKeyErr != nil {
			// 	return nil, errors.New("Error with file HMAC key gen")
			// }
			// var tailFileHMACEval, tailFileHMACEvalErr = userlib.HMACEval(tailHMACKey[:16], tailFileSS.Ciphertext)
			// if tailFileHMACEvalErr != nil {
			// 	return nil, errors.New("Error computing tail file HMAC Shared User")
			// }
			// var verifyTailHMAC = userlib.HMACEqual(tailFileSS.HMAC, tailFileHMACEval)
			// if !verifyTailHMAC {
			// 	return nil, errors.New("Tail File Tamper Shared user")
			// }

			// Get tail file
			var tailFile File
			json.Unmarshal(userlib.SymDec(LLB.DecryptionKey[:16], tailFileSS.Ciphertext), &tailFile)

			// Get a new file
			var newFileByte []byte
			var newFileSS SecureStore
			var newFile = ogFileItself
			var newContent = ogFileItself.Text
			for i := 0; i < 10000; i++ {
				fmt.Printf("starting iteration %d\n", i)

				// If the end of the file has been reached
				if newFile.NextPointer == ogFileItself.TailPointer {
					if i == 0 {
						break
					} else {
						var newFileSSByte, newFileByteSSErr = userlib.DatastoreGet(newFile.NextPointer)
						if newFileByteSSErr != true {
							return nil, errors.New("Error finding next file efficient Append")
						}
						json.Unmarshal(newFileSSByte, &newFileSS)
						newFileByte = userlib.SymDec(LLB.DecryptionKey[:16], newFileSS.Ciphertext)
						json.Unmarshal(newFileByte, &newFile)
						newContent = append(newContent, newFile.Text...)
						fmt.Printf("new content is %s\n", newContent)
						break
					}
				}

				// Get the next file
				var newFileSSByte, newFileByteSSErr = userlib.DatastoreGet(newFile.NextPointer)
				if newFileByteSSErr != true {
					return nil, errors.New("Error finding next file efficient Append")
				}
				json.Unmarshal(newFileSSByte, &newFileSS)
				newFileByte = userlib.SymDec(LLB.DecryptionKey[:16], newFileSS.Ciphertext)
				json.Unmarshal(newFileByte, &newFile)

				// Append new content
				newContent = append(newContent, newFile.Text...)
				fmt.Printf("new content is %s\n", newContent)
			}

			// Condense all appends into the header file
			ogFileItself.Text = newContent
			ogFileItself.NextPointer = ogFileItself.TailPointer

			//marshal back after overwrite
			var overwriteByte, overwriteByteErr = json.Marshal(ogFileItself)
			if overwriteByteErr != nil {
				return nil, errors.New("Err computing HMAC OgFileSS Err")
			}
			ogFileSS.Ciphertext = userlib.SymEnc(LLB.DecryptionKey[:16], userlib.RandomBytes(16), overwriteByte)

			// Verify HMAC on ciphertext inside secureStruct
			var ogFSSHMAC2, ogFSSHMACErr2 = userlib.HashKDF(LLB.DecryptionKey[:16], []byte("File HMAC Key"))
			if ogFSSHMACErr2 != nil {
				return nil, errors.New("Err computing Hash Store File")
			}
			var ogFileSSHMAC2, ogFileSSHMACErr = userlib.HMACEval(ogFSSHMAC2[:16], ogFileSS.Ciphertext)
			if ogFileSSHMACErr != nil {
				return nil, errors.New("Err computing HMAC OgFileSS Err")
			}
			ogFileSS.HMAC = ogFileSSHMAC2

			// Store securestruct back in datastore
			var secureByte, secureError = json.Marshal(ogFileSS)
			if secureError != nil {
				return nil, errors.New("Error marshaling secure struct")
			}
			userlib.DatastoreSet(LLB.EncFile, secureByte)

			return newContent, nil
		}
		return nil, nil
	}
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// Check if the recipient user exists
	var pubKey, keyExists = userlib.KeystoreGet(recipientUsername)
	if !keyExists {
		return uuid.Nil, errors.New("That user does not exist.")
	}

	// Recreating the rootkey
	var salt = userlib.Hash([]byte(userdata.Username))
	var rootKey = userlib.Argon2Key([]byte(userdata.Password), salt, 16)

	// Creating the datastoreKey for the OWNER for the PLB
	var ownerDSKey, err1 = userlib.HashKDF(rootKey, []byte("PLB"+filename))
	var ownerUUIDKey, err2 = uuid.FromBytes(ownerDSKey[:16])
	if (err1 != nil) || (err2 != nil) {
		return uuid.Nil, errors.New("Error 1")
	}

	// Creating the datastoreKey for a SHARED user
	var shareDSKey, err3 = userlib.HashKDF(rootKey, []byte("PLBLLB"+filename))
	var shareUUIDKey, err4 = uuid.FromBytes(shareDSKey[:16])
	if (err3 != nil) || (err4 != nil) {
		return uuid.Nil, errors.New("Error 2")
	}

	// Get the owner copy from datastore (if it exists)
	var ownerLockboxEnc, exists = userlib.DatastoreGet(ownerUUIDKey)

	// Get the shared copy from datastore (if it exists)
	var shareLockboxEnc, otherExists = userlib.DatastoreGet(shareUUIDKey)

	if !exists && !otherExists {
		return uuid.Nil, errors.New("File not found.")
	}

	// Get the lockbox; we don't know if it points straight to file or not (will be determined below)
	var personalLockbox PersonalLockbox
	var personalLockboxByte []byte // will be used in if statements

	// Create the Invitation (will be used IN and AFTER if statements)
	var invitation Invitation

	// If the user is NOT the owner (lockbox will contain another lockbox), get the lineageLockbox
	if otherExists {

		// Decrypt the personal lockbox and get the physical lockbox
		var shareDecKey, err5 = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
		personalLockboxByte = userlib.SymDec(shareDecKey[:16], shareLockboxEnc)
		var err6 = json.Unmarshal(personalLockboxByte, &personalLockbox)
		if (err5 != nil) || (err6 != nil) {
			return uuid.Nil, errors.New("Error 3.")
		}

		// Set the pointer to the lineage lockbox in invitation
		invitation.EncLockboxPointer = personalLockbox.FileOrLockBoxPointer

		// Set the decryption key for the invitation
		invitation.DecryptionKey = personalLockbox.DecryptionKey
	}

	// If the user is the OWNER (lockbox will point straight to the file), a lineage lockbox is created
	if exists {

		//Setup variable for NEW lockbox
		var lineageLockbox Lockbox

		// Decrypt the personal lockbox and get the physical lockbox
		var ownerDecKey, err7 = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
		personalLockboxByte = userlib.SymDec(ownerDecKey[:16], ownerLockboxEnc)
		var err8 = json.Unmarshal(personalLockboxByte, &personalLockbox)
		if (err7 != nil) || (err8 != nil) {
			return uuid.Nil, errors.New("Error 4.")
		}

		// Set the files ctext and dkey in the lineage lockbox
		lineageLockbox.DecryptionKey = personalLockbox.DecryptionKey
		lineageLockbox.EncFile = personalLockbox.FileOrLockBoxPointer

		// Creating the encryption key and IV for the lineage Lockbox
		var iv2 = userlib.RandomBytes(16)
		var encryptionKey, err9 = userlib.HashKDF(rootKey, []byte("LLB ENC Key"))
		if err9 != nil {
			return uuid.Nil, errors.New("Error5.")
		}

		// Encrypt the lineage Lockbox
		var lineageData, err10 = json.Marshal(lineageLockbox)
		var lineageLockboxEnc = userlib.SymEnc(encryptionKey[:16], iv2, lineageData)
		if err10 != nil {
			return uuid.Nil, errors.New("Error6.")
		}

		// Create the lineage lockbox datastore key
		var lineageDatastoreKey, err11 = userlib.HashKDF(rootKey, []byte("LLB"+filename+recipientUsername))
		var uuidLineageKey, err12 = uuid.FromBytes(lineageDatastoreKey[:16])
		if (err11 != nil) || (err12 != nil) {
			return uuid.Nil, errors.New("Error7.")
		}

		// Set the lineage lockbox in datastore
		userlib.DatastoreSet(uuidLineageKey, lineageLockboxEnc)

		// Set the decryption key for the invitation
		invitation.DecryptionKey = encryptionKey

		// Set the pointer to the lineage lockbox in invitation
		invitation.EncLockboxPointer = uuidLineageKey

		// SETTING THE SHARED USERS LIST

		// Get the encrypted shared user list (which might or might not exist)
		var sharedUserListEnc = personalLockbox.SharedUsersList
		var sharedUserList map[string]userlib.UUID

		// Some helpful variables
		var listKey, err13 = userlib.HashKDF(rootKey, []byte("Shared User List"+filename))
		var listHmacKey, err14 = userlib.HashKDF(listKey[:16], []byte("HMAC"))
		var sharedUserListByte []byte
		if (err13 != nil) || (err14 != nil) {
			return uuid.Nil, errors.New("Error8.")
		}

		// Check if shared user list even exists
		if sharedUserListEnc == nil {
			sharedUserList = make(map[string]userlib.UUID)
		} else {

			// Check HMAC on list
			var currListHMAC, err15 = userlib.HMACEval(listHmacKey[:16], sharedUserListEnc)
			if err15 != nil {
				return uuid.Nil, errors.New("Error9.")
			}
			var equal = userlib.HMACEqual(currListHMAC, personalLockbox.ListHMAC)
			if !equal {
				return uuid.Nil, errors.New("Can not continue due to malicious activity.")
			}

			// Decrypt list
			sharedUserListByte = userlib.SymDec(personalLockbox.DecryptionListKey[:16], sharedUserListEnc)
			var err16 = json.Unmarshal(sharedUserListByte, &sharedUserList)
			if err16 != nil {
				return uuid.Nil, errors.New("Error10.")
			}
		}

		// Add recipient to list
		sharedUserList[recipientUsername] = uuidLineageKey

		// Encrypt list and add back in personalLockbox w/ decryption key
		var iv = userlib.RandomBytes(16)
		sharedUserListByte, err1 = json.Marshal(sharedUserList)
		sharedUserListEnc = userlib.SymEnc(listKey[:16], iv, sharedUserListByte)
		personalLockbox.SharedUsersList = sharedUserListEnc
		personalLockbox.DecryptionListKey = listKey
		if err1 != nil {
			return uuid.Nil, errors.New("Error11.")
		}

		// Recompute HMAC and put that in personalLockbox
		var listHMAC, err17 = userlib.HMACEval(listHmacKey[:16], sharedUserListEnc)
		personalLockbox.ListHMAC = listHMAC
		if err17 != nil {
			return uuid.Nil, errors.New("Error12.")
		}

		// Re-encrypt personal lockbox with updated shared user list (MAC and decryption key for list too)
		var personalKey, err18 = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
		iv = userlib.RandomBytes(16)
		var personalLockboxByte, err19 = json.Marshal(personalLockbox)
		var personalLockboxEnc = userlib.SymEnc(personalKey[:16], iv, personalLockboxByte)
		if (err18 != nil) || (err19 != nil) {
			return uuid.Nil, errors.New("Error13.")
		}

		// Place personalLockbox back into datastore
		userlib.DatastoreSet(ownerUUIDKey, personalLockboxEnc)

	}

	// Encrypt the invitation
	var inviteData, err20 = json.Marshal(invitation)
	var invEncKey = userlib.RandomBytes(16)
	var invIV = userlib.RandomBytes(16)
	var invEnc = userlib.SymEnc(invEncKey[:16], invIV, inviteData)
	if err20 != nil {
		return uuid.Nil, errors.New("Error14.")
	}

	// Compute the HMAC of the encrypted invitation
	var inviteHmacKey, err21 = userlib.HashKDF(invEncKey, []byte("HMAC"))
	var inviteHMAC, err22 = userlib.HMACEval(inviteHmacKey[:16], invEnc)
	if (err21 != nil) || (err22 != nil) {
		return uuid.Nil, errors.New("Error15.")
	}

	// Encrypt the decryption key for the invitation with recieving users public key
	var keyEnc, err25 = userlib.PKEEnc(pubKey, invEncKey)
	if err25 != nil {
		return uuid.Nil, err25
	}

	// Create invitation Carrier and input the invite and HMAC
	var carrier InviteCarrier
	carrier.DecryptionKey = keyEnc
	carrier.EncInvite = invEnc
	carrier.HMAC = inviteHMAC
	var carrierByte, err24 = json.Marshal(carrier)
	if err24 != nil {
		return uuid.Nil, err24
	}

	// Create Datastore key to store invitation CARRIER
	var newDatastoreKey, err26 = userlib.HashKDF(rootKey, []byte("Invite Datastore Key"+filename))
	var invitationPtrKey, err27 = uuid.FromBytes(newDatastoreKey[:16])
	if (err26 != nil) || (err27 != nil) {
		return uuid.Nil, errors.New("Error19.")
	}

	// Store invitation ptr in datastore
	userlib.DatastoreSet(invitationPtrKey, carrierByte)

	return invitationPtrKey, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	// Recreating the rootkey
	var salt = userlib.Hash([]byte(userdata.Username))
	var rootKey = userlib.Argon2Key([]byte(userdata.Password), salt, 16)

	// Creating the datastoreKey for the OWNER
	var ownerDSKey, err1 = userlib.HashKDF(rootKey, []byte("PLB"+filename))
	var ownerUUIDKey, err2 = uuid.FromBytes(ownerDSKey[:16])
	if (err1 != nil) || (err2 != nil) {
		return errors.New("Error.")
	}

	// Creating the datastoreKey for a SHARED user
	var shareDSKey, err3 = userlib.HashKDF(rootKey, []byte("PLBLLB"+filename))
	var shareUUIDKey, err4 = uuid.FromBytes(shareDSKey[:16])
	if (err3 != nil) || (err4 != nil) {
		return errors.New("Error.")
	}

	// Get the owner copy from datastore (if it exists)
	var err5, exists = userlib.DatastoreGet(ownerUUIDKey)

	// Get the shared copy from datastore (if it exists)
	var err6, otherExists = userlib.DatastoreGet(shareUUIDKey)

	if (err5 != nil) || (err6 != nil) {
		return errors.New("Error.")
	}

	// Check if a file with filename already exists in the namespace
	if exists || otherExists {
		return errors.New("That filename already exists.")
	}

	// Get the invite CARRIER from the datastore
	var carrier InviteCarrier
	var carrierByte, carrierExists = userlib.DatastoreGet(invitationPtr)
	if !carrierExists {
		return errors.New("Something has gone wrong.")
	}
	var err8 = json.Unmarshal(carrierByte, &carrier)
	if err8 != nil {
		return err8
	}

	// Check the INTEGRITY (HMAC) of the invitation
	var invKey, err7 = userlib.PKEDec(userdata.SecretKey, carrier.DecryptionKey)
	if err7 != nil {
		return err7
	}
	var inviteHmacKey, err10 = userlib.HashKDF(invKey, []byte("HMAC"))
	var inviteHMAC, err11 = userlib.HMACEval(inviteHmacKey[:16], carrier.EncInvite)
	var match = userlib.HMACEqual(inviteHMAC, carrier.HMAC)
	if !match {
		return errors.New("Can not garuntee integrity of invitation.")
	}
	if (err10 != nil) || (err11 != nil) {
		return errors.New("Error.")
	}

	// Decrypt the CARRIER to get the invitation
	var invitation Invitation
	var invitationByte = userlib.SymDec(invKey[:16], carrier.EncInvite)
	var err12 = json.Unmarshal(invitationByte, &invitation)
	if err12 != nil {
		return errors.New("Error.")
	}

	// Check if the invitation is no longer valid due to revocation
	var lineageLB Lockbox
	var lineageEnc, err13 = userlib.DatastoreGet(invitation.EncLockboxPointer)
	var lineageBytes = userlib.SymDec(invitation.DecryptionKey[:16], lineageEnc)
	var err14 = json.Unmarshal(lineageBytes, &lineageLB)
	if (!err13) || (err14 != nil) {
		return errors.New("Error.")
	}

	var secure SecureStore
	var secureByte, _ = userlib.DatastoreGet(lineageLB.EncFile)
	var err15 = json.Unmarshal(secureByte, &secure)
	if err15 != nil {
		return errors.New("Error.")
	}

	var fileHMACKey, err16 = userlib.HashKDF(lineageLB.DecryptionKey, []byte("File HMAC Key"))
	var fileHMAC, err17 = userlib.HMACEval(fileHMACKey[:16], secure.Ciphertext)
	var equal = userlib.HMACEqual(fileHMAC, secure.HMAC)
	if !equal {
		return errors.New("Access to this file has been revoked.")
	}
	if (err16 != nil) || (err17 != nil) {
		return errors.New("Error.")
	}

	// Create a personal lockbox with the contents of invitation and nil
	var newPLB PersonalLockbox
	newPLB.DecryptionKey = invitation.DecryptionKey
	newPLB.FileOrLockBoxPointer = invitation.EncLockboxPointer
	newPLB.DecryptionListKey = nil
	newPLB.ListHMAC = nil
	newPLB.SharedUsersList = nil

	// Encrypt the PLB before placing in datastore
	var plbByte, err18 = json.Marshal(newPLB)
	var newIV = userlib.RandomBytes(16)
	var plbEncKey, err19 = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
	var plbEnc = userlib.SymEnc(plbEncKey[:16], newIV, plbByte)
	if (err18 != nil) || (err19 != nil) {
		return errors.New("Error.")
	}

	// Add the new PLB to the datastore (+ "shared" in key so for future reference it is known to be a shared file)
	userlib.DatastoreSet(shareUUIDKey, plbEnc)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	// Recreating the rootkey
	var salt = userlib.Hash([]byte(userdata.Username))
	var rootKey = userlib.Argon2Key([]byte(userdata.Password), salt, 16)

	// Creating the datastoreKey
	var dsKey, _ = userlib.HashKDF(rootKey, []byte("PLB"+filename))
	var uuidKey, _ = uuid.FromBytes(dsKey[:16])

	// Get the encrypted PBL from the datastore
	var pblEnc, exists = userlib.DatastoreGet(uuidKey)

	// Check if the file exists in the namespace
	if !exists {
		return errors.New("That file does not exist.")
	}

	// Decrypt the encrypted PBL
	var pblEncKey, err1 = userlib.HashKDF(rootKey, []byte("ENC Key"+filename))
	var pblByte = userlib.SymDec(pblEncKey[:16], pblEnc)
	var pbl PersonalLockbox
	var err2 = json.Unmarshal(pblByte, &pbl)
	if (err1 != nil) || (err2 != nil) {
		return errors.New("Error.")
	}

	// Get and decrypt the shared user list
	var sharedUserList map[string]userlib.UUID
	if pbl.SharedUsersList == nil {
		return errors.New("That file is not currently shared with the specified user.")
	}
	var sharedUserListByte = userlib.SymDec(pbl.DecryptionListKey[:16], pbl.SharedUsersList)
	var err3 = json.Unmarshal(sharedUserListByte, &sharedUserList)
	if err3 != nil {
		return errors.New("Error.")
	}

	// Check if the file was ever shared with the user
	var _, userShared = sharedUserList[recipientUsername]
	if !userShared {
		return errors.New("That file is not currently shared with the specified user.")
	}

	// Get the SECURE struct
	var secureByte, secureExists = userlib.DatastoreGet(pbl.FileOrLockBoxPointer)
	if !secureExists {
		return errors.New("That file does not exist.")
	}

	// Decrypt the SECURE struct and get the FILE struct
	var secure SecureStore
	var err5 = json.Unmarshal(secureByte, &secure)
	var fileByte = userlib.SymDec(pbl.DecryptionKey[:16], secure.Ciphertext)
	var file File
	var err6 = json.Unmarshal(fileByte, &file)
	if (err5 != nil) || (err6 != nil) {
		return errors.New("Error.")
	}

	// Re-encrypt the FILE struct and set in SECURE struct
	var newRandomKey = userlib.RandomBytes(16)
	fileByte, err3 = json.Marshal(file)
	var iv = userlib.RandomBytes(16)
	var ciphertext = userlib.SymEnc(newRandomKey[:16], iv, fileByte)
	secure.Ciphertext = ciphertext
	if err3 != nil {
		return errors.New("Error.")
	}

	// Set new HMAC for the ciphertext (enc file struct) and set in SECURE struct
	var newHMACKey, err8 = userlib.HashKDF(newRandomKey, []byte("File HMAC Key"))
	var newHMAC, err9 = userlib.HMACEval(newHMACKey[:16], ciphertext)
	secure.HMAC = newHMAC
	if (err8 != nil) || (err9 != nil) {
		return errors.New("Error.")
	}

	// Write the new secure struct to the OLD secure structs place in Datastore
	secureByte, err3 = json.Marshal(secure)
	userlib.DatastoreSet(pbl.FileOrLockBoxPointer, secureByte)
	if err3 != nil {
		return errors.New("Error.")
	}

	// Add the new decryption key to the owners PLB
	pbl.DecryptionKey = newRandomKey

	// Update all users lineage lockboxes in sharedUsersList with the new decryption
	for user, lineageDSKey := range sharedUserList {

		// For all users that are NOT the revoked user
		if user != recipientUsername {

			// Get the lineage LB from datastore
			var lineageEnc, lineageExists = userlib.DatastoreGet(lineageDSKey)
			if !lineageExists {
				return errors.New("Error.")
			}

			// Decrypt the lineage LB
			var lineageEncKey, err12 = userlib.HashKDF(rootKey, []byte("LLB ENC Key"))
			var lineageLBByte = userlib.SymDec(lineageEncKey[:16], lineageEnc)
			var lineageLB Lockbox
			var err13 = json.Unmarshal(lineageLBByte, &lineageLB)
			if (err12 != nil) || (err13 != nil) {
				return errors.New("Error.")
			}

			// Set the new decryption key into the lockbox
			lineageLB.DecryptionKey = newRandomKey

			// Re-encrypt the lineage lockbox
			var lineageByte, err14 = json.Marshal(lineageLB)
			var lineageIV = userlib.RandomBytes(16)
			lineageEnc = userlib.SymEnc(lineageEncKey[:16], lineageIV, lineageByte)
			if err14 != nil {
				return errors.New("Error.")
			}

			// Store the lineage lockbox back into datastore
			userlib.DatastoreSet(lineageDSKey, lineageEnc)
		}
	}

	// Delete the deleted user from the shared list
	delete(sharedUserList, recipientUsername)

	// Re-encrypt shared user list
	var listKey, _ = userlib.HashKDF(rootKey, []byte("Shared User List"+filename))
	var byteList, _ = json.Marshal(sharedUserList)
	var listEnc = userlib.SymEnc(listKey[:16], userlib.RandomBytes(16), byteList)
	pbl.SharedUsersList = listEnc
	pbl.DecryptionListKey = listKey

	// HMAC list again
	var listHmacKey, _ = userlib.HashKDF(listKey[:16], []byte("HMAC"))
	var listHMAC, _ = userlib.HMACEval(listHmacKey, listEnc)
	pbl.ListHMAC = listHMAC

	// Re-encrypt the PLB
	pblByte, err3 = json.Marshal(pbl)
	var newIV = userlib.RandomBytes(16)
	pblEnc = userlib.SymEnc(pblEncKey[:16], newIV, pblByte)
	if err3 != nil {
		return errors.New("Error.")
	}

	// Write the PLB back into datastore
	userlib.DatastoreSet(uuidKey, pblEnc)

	return nil
}
