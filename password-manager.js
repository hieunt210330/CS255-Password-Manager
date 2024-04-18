"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes, cipherIV, decipherIV } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const crypto = require('crypto');

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
	/**
	 * Initializes the keychain using the provided information. Note that external
	 * users should likely never invoke the constructor directly and instead use
	 * either Keychain.init or Keychain.load. 
	 * Arguments:
	 *  You may design the constructor with any parameters you would like. 
	 * Return Type: void
	 */
	constructor() 
	{

		this.data = {
			kvs: {}
		/* Store member variables that you intend to be public here
			(i.e. information that will not compromise security if an adversary sees) */
		};
		this.secrets = {
			master_salt: null,
			master_key: null,
			hmac_key: null,
			hmac_salt: null,
			magic: null
		/* Store member variables that you intend to be private here
			(information that an adversary should NOT see). */
		};

		this.ready = false;

	};

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
	static async init(password) 
	{
		if (password.length > MAX_PASSWORD_LENGTH)
		{
			throw "Password too long.";
		}
		
		var keychain = new Keychain();

		keychain.secrets.master_salt = crypto.randomBytes(32);
		keychain.secrets.master_key = crypto.pbkdf2Sync(password, keychain.secrets.master_salt, PBKDF2_ITERATIONS, 32, 'sha256');

		keychain.secrets.hmac_key = crypto.createHash('sha256').update(keychain.secrets.master_key).digest('hex');
		keychain.secrets.hmac_salt = crypto.randomBytes(32);

		keychain.secrets.magic = cipherIV("Recurse", keychain.secrets.master_key);
		if (keychain.secrets.magic === null) 
		{
			keychain.ready = false;
			throw "Magic keyword encryption failed.";
		}
		keychain.ready = true;
		return keychain;
	}

	/**
	* Loads the keychain state from the provided representation (repr). The
	* repr variable will contain a JSON encoded serialization of the contents
	* of the KVS (as returned by the dump function). The trustedDataCheck
	* is an *optional* SHA-256 checksum that can be used to validate the 
	* integrity of the contents of the KVS. If the checksum is provided and the
	* integrity check fails, an exception should be thrown. You can assume that
	* the representation passed to load is well-formed (i.e., it will be
	* a valid JSON object).Returns a Keychain object that contains the data
	* from repr. 
	*
	* Arguments:
	*   password:           string
	*   repr:               string
	*   trustedDataCheck: string
	* Return Type: Keychain
	*/
	static async load(password, repr, trustedDataCheck) 
	{
		if (password.length > MAX_PASSWORD_LENGTH)
		{
			throw "Password too long.";
		}
		var store = repr;
		if (trustedDataCheck !== undefined &&
			crypto.createHash('sha256').update(store).digest('hex') != trustedDataCheck)
		{
			throw "SHA-256 validation failed!";
		}
		else 
		{
			var keychain = new Keychain();

			var new_keychain = await JSON.parse(repr);

			new_keychain.secrets.master_salt = decodeBuffer(new_keychain.secrets.master_salt);
			new_keychain.secrets.master_key = decodeBuffer(new_keychain.secrets.master_key);
			new_keychain.secrets.hmac_salt = decodeBuffer(new_keychain.secrets.hmac_salt);
			
			var password_key = crypto.pbkdf2Sync(password, new_keychain.secrets.master_salt, PBKDF2_ITERATIONS, 32, 'sha256');

			var plaintext = decipherIV(new_keychain.secrets.magic.toString('hex'), password_key);

			if (plaintext === "Recurse") 
			{
				keychain.secrets.master_key = password_key;
				keychain.secrets.hmac_key = crypto.createHash('sha256').update(keychain.secrets.master_key).digest('hex');

				keychain.data = new_keychain.data;
				keychain.secrets = new_keychain.secrets;
				keychain.ready = true;
				return keychain;
			}
			else
			{
				throw Error("Wrong password.");
			}
		}
	};

	/**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
	async dump() 
  	{
		var encoded_store = JSON.stringify(
		{ 
			data: this.data, 
			secrets: 
			{
				master_salt: encodeBuffer(this.secrets.master_salt),
				master_key: encodeBuffer(this.secrets.master_key),
				hmac_key: this.secrets.hmac_key,
				hmac_salt: encodeBuffer(this.secrets.hmac_salt),
				magic: this.secrets.magic
			}, 
			kvs: this.data.kvs,
			 
		});
		var checksum = crypto.createHash('sha256').update(encoded_store).digest('hex');
		return [encoded_store, checksum];
	};

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
	async get(name) 
	{
		if (!this.ready)
		{
			throw "Keychain not initialized.";
		}
		if (this.secrets.hmac_key === undefined) 
		{
			this.secrets.hmac_salt = crypto.randomBytes(32);
			this.secrets.hmac_key = crypto.createHash('sha256').update(this.secrets.master_key).digest('hex');
		}
		var name_digest = crypto.createHmac('sha256', this.secrets.hmac_key).update(name).digest('hex');
		if (this.data.kvs[name_digest]) 
		{
			var plaintext = decipherIV(this.data.kvs[name_digest], Buffer.from(this.secrets.master_key));
			return plaintext;
		} 
		else 
		{
			return null;
		}
	};

	/** 
	 * Inserts the domain and associated data into the KVS. If the domain is
	 * already in the password manager, this method should update its value. If
	 * not, create a new entry in the password manager.
	 *
	 * Arguments:
	 *   name: string
	 *   value: string
	 * Return Type: void
	 */
	async set(name, value) 
	{
		if (!this.ready) 
		{
			throw "Keychain not initialized.";
		}
		var name_digest = crypto.createHmac('sha256', this.secrets.hmac_key).update(name).digest('hex');
		var enc_val = cipherIV(value, this.secrets.master_key);
		if (enc_val !== null)
		{
			this.data.kvs[name_digest] = enc_val;
		}
		else
		{
			throw "Encryption failed.";
		}
	};

	/**
		* Removes the record with name from the password manager. Returns true
		* if the record with the specified name is removed, false otherwise.
		*
		* Arguments:
		*   name: string
		* Return Type: Promise<boolean>
	*/
	async remove(name) {
		if (!this.ready)
		{
			throw "Keychain not initialized.";
		}
		var name_digest = crypto.createHmac('sha256', this.secrets.hmac_key).update(name).digest('hex');
		if (this.data.kvs[name_digest]) 
		{
			delete this.data.kvs[name_digest];
			return true;
		} 
		else 
		{
			return false;
		}
	};

};

module.exports = { Keychain }
