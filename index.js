"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
// Cryptography Library
const crypto = __importStar(require("crypto"));
/**
    Fundamental purpose of any cryptocurrencies Transaction
    Transfer funds from one user to another in a TRANSACTION
 */
class Transaction {
    /**
     *
     * @param amount number - of transaction to transfer, dennominated in coins
     * @param payer number - paying the money - PUBLIC KEY
     * @param payee string - recieving the money - PUBLIC KEY
     */
    constructor(amount, payer, payee) {
        this.amount = amount;
        this.payer = payer;
        this.payee = payee;
    }
    // Convert the object to a string
    toString() {
        return JSON.stringify(this);
    }
}
/**
    Continer for multiple transaction
    Linked list of transaction
    Hashes CANNOT recreate the value that was hashed
    Hashe CAN validate that two values are identical by comparing thier hashes
 */
class Block {
    /**
     *
     * @param prevHash string - Hash of the previous transaction
     * @param transaction transaction - object
     * @param timestamp Date - Timestamp of the current transaction
     */
    constructor(prevHash, transaction, timestamp = Date.now()) {
        this.prevHash = prevHash;
        this.transaction = transaction;
        this.timestamp = timestamp;
        // One-time-use random number generator
        this.nonce = Math.round(Math.random() * 999999999);
    }
    /**
     * Get that stringifies the object itself
     * Then it implements a hash function with the SHA256 algorithm
     * return value in hexadecimal string format
     */
    get hash() {
        const str = JSON.stringify(this);
        const hash = crypto.createHash('SHA256'); // one way cryptographic function
        hash.update(str);
        return hash.digest('hex');
    }
}
/**
 * Linked list of blocks
 * There should be only ONE blockchain (or chain)
 */
class Chain {
    constructor() {
        // Genesis Block
        this.chain = [new Block('', new Transaction(100, 'genesis', 'satoshi'))];
    }
    // Grab the last block in the chain
    get lastBlock() {
        return this.chain[this.chain.length - 1];
    }
    // Attempt to find a number that, when added to the nonce, produces a hash that
    // has 4 zeroes. Can only be done by brute force
    mine(nonce) {
        let solution = 1;
        console.log('mining...');
        while (true) {
            // Message Digest Algorithm
            const hash = crypto.createHash('MD5');
            hash.update((nonce + solution).toString()).end();
            const attempt = hash.digest('hex');
            /**
             * We continue to create new hashes in the while loop until we find a solution
             * that starts with 4 zeroes. When we find it, we return it and send it to
             * other nodes where it can be verified and the block can finally be confirmed.
             */
            if (attempt.substring(0, 4) === '0000') {
                console.log(`Solved: ${solution}`);
                return solution;
            }
            solution += 1;
        }
    }
    /**
     *
     * @param transaction Transaction object
     * @param senderPublicKey Senders public key
     * @param signature A signature we can verify before adding a new block
     */
    addBlock(transaction, senderPublicKey, signature) {
        const verifier = crypto.createVerify('SHA256');
        verifier.update(transaction.toString());
        const isValid = verifier.verify(senderPublicKey, signature);
        // Only add block if the signature is valid
        if (isValid) {
            const newblock = new Block(this.lastBlock.hash, transaction);
            // miner
            this.mine(newblock.nonce);
            this.chain.push(newblock);
        }
    }
}
Chain.instance = new Chain(); // singleton instance for only one chain
/**
 * Securelly sends coins back and forth
 * Wrapper for a private key and a public key
 * public key -> Recieving coins
 * private key -> Spending coins
 */
class Wallet {
    constructor() {
        /**
         * Full algorithm that can encrypt AND decrypt data, if you have the propper
         * key to do so. These are called Asymmetric systems.
         * To ENCRYPT -> use the public key to convert to cypher text (unreadable)
         * To DECRYPT -> use the private key to convert back to its original format
         *
         * More importantly, you can use the algorithm to create a digital signature.
         * The message will have the private key included, and the reciever will
         * verify the validity of the message by checking the signature of it (with
         * the private key included) with the public key.
         *
         * Format the keypair as strings. PEM format is important.k
         */
        const keypair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        this.privateKey = keypair.privateKey;
        this.publicKey = keypair.publicKey;
    }
    /**
     *
     * @param amount Amount of money being sended
     * @param payeePublicKey Recievers public key
     */
    sendMoney(amount, payeePublicKey) {
        const transaction = new Transaction(amount, this.publicKey, payeePublicKey);
        // Create a signature using the transaction data as the value
        const sign = crypto.createSign('SHA256');
        sign.update(transaction.toString()).end();
        /**
         * Create a signature by signing it with the private key.
         * Its like a one time password.
         * PrivateKey + Transaction <-> PublicKey
         */
        const signature = sign.sign(this.privateKey);
        // Instance and add this block to the blockchain.
        // In real life, those values would be transferred via internet
        Chain.instance.addBlock(transaction, this.publicKey, signature);
    }
}
// Example usage
const Alice = new Wallet();
const Bob = new Wallet();
const Carol = new Wallet();
Alice.sendMoney(50, Bob.publicKey);
Bob.sendMoney(23, Bob.publicKey);
Carol.sendMoney(5, Bob.publicKey);
console.log(Chain.instance);
