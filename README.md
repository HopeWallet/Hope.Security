<p align="center">
  <img src="Hope.Security/Hope_Background.png?raw=true" alt="Hope" align="center" width="785px" height="328px"/>
</p>

| Code Quality |
| :----|
| [![CodeFactor][0]][1] |

[0]: https://www.codefactor.io/repository/github/hopewallet/hope.security/badge
[1]: https://www.codefactor.io/repository/github/hopewallet/hope.security

# Hope.Security

Cross platform security library which implements secure PBKDF2 password hashing, symmetric encryption, and various other security principals.

## Installation

The required dlls for the Hope.Security library are located in the [Hope.Security releases](https://github.com/HopeWallet/Hope.Security/releases). Download the latest Hope.Security zip file and add all required dlls to your project references.

## Usage

The usage for the Hope.Security library are split up into several different sections. There is a section which implements Symmetric Encryption, another section which implements secure hashing of byte/string data, as well as secure PBKDF2 password hashing.

### Symmetric Encryption

The Hope.Security library implements very simple classes for symmetric encryption. You have two different types of encryption: data encryption and memory encryption through the ```SecureDataEncryptor``` and ```SecureMemoryEncryptor``` classes.

Both classes are similar to the ```AdvancedSecureRandom``` class from the Hope.Random library in that they can take many different objects to use as encryption entropy.

It is important to note that there must be some entropy in use at some point for the encryption. The entropy can be included either in the Encrypt method, or it must be included in the creation of the new instance of the ```SecureDataEncryptor``` or ```SecureMemoryEncryptor```.

#### Data Encryption

Data encryption through the ```SecureDataEncryptor``` is used for long term encrypted data storage which can be encrypted and decrypted over long periods of time and multiple sessions.

See the following code for an example of ```SecureDataEncryptor```.

```c#
string encryptedText = string.Empty;

// Encrypts some data with the entropy "entropy", "14235", and "true".
using (SecureDataEncryptor dataEncryptor = new SecureDataEncryptor("entropy", 14235, true));
{
  encryptedText = dataEncryptor.Encrypt("this is my data");
}

// Decrypts the data using the same objects as entropy.
using (SecureDataEncryptor dataEncryptor = new SecureDataEncryptor("entropy", 14235, true));
{
  string decryptedText = dataEncryptor.Decrypt(encryptedText);
}
```

The example above uses entropy in the initialization of the ```SecureDataEncryptor```.

See the following code for an example of encrypting with some entropy in the Encrypt/Decrypt methods.

```c#
byte[] entropy = new byte[] { 5, 18, 24, 29, 2, 128 };

string encryptedText = string.Empty;

// Encrypts some data with the initial initialization entropy of the byte data, as well as some arbitrary text "238hwuosdfouh".
// Also uses the text "additional entropy" when encrypting the data with the Encrypt method.
using (SecureDataEncryptor dataEncryptor = new SecureDataEncryptor(entropy, "238hwuosdfouh"))
{
  encryptedText = dataEncryptor.Encrypt("this is my data", "additional entropy");
}

using (SecureDataEncryptor dataEncryptor = new SecureDataEncryptor(entropy, "238hwuosdfouh"))
{
  string decryptedText = dataEncryptor.Decrypt("this is my data", "additional entropy");
}
```

#### Memory Encryption

Memory encryption through the ```SecureMemoryEncryptor``` is used for short term encrypted data storage which can only be encrypted with the same ```SecureMemoryEncryptor``` instance and over one session of lifetime.

See the following example for encrypting some temporary data.

```c#
SecureMemoryEncryptor memoryEncryptor = new SecureMemoryEncryptor();

// This is the data we want to encrypt
byte[] data = new byte[] { 5, 18, 39, 99 };

//Encrypts the byte data. After the original byte data is encrypted, the original data array is empty and contains no data at all.
byte[] encryptedData = memoryEncryptor.Encrypt(data);

// Decrypts the encrypted byte data. The same SecureMemoryEncryptor instance must be used to decrypt.
byte[] decryptedData = memoryEncryptor.Decrypt(encryptedData);
```

Unlike the ```SecureDataEncryptor```, you can encrypt some data without any entropy at all. This is because the ```SecureMemoryEncryptor``` generates its own byte entropy each time it is initialized. This is why you always need to use the same ```SecureMemoryEncryptor``` instance to decrypt data you encrypted.

See the [Hope.Security.Tests](https://github.com/HopeWallet/Hope.Security/tree/master/Hope.Security/Hope.Security.Tests) folder for more example uses of the ```SecureDataEncryptor``` and ```SecureMemoryEncryptor```.

### Data Hashing

The Hope.Security library implements many different methods for hashing some arbitrary bytes or string of text. Hashing string data or bytes is very common when obscuring or comparing data.

Take a look at the following code which shows how you can hash some data.

```c#
// Gets the SHA3-256 hash of the text "my text"
string hashedText = HashGenerators.SHA3_256("my text");

// Gets the Keccak-256 hash of some byte data
byte[] data = new byte[] { 1, 42, 89, 92, 90, 90, 4, 14 };
byte[] hashedData = HashGenerators.Keccak_256(data);
```

As you can see, hashing some data is extremely simple and convenient. You are exposed to a variety of algorithms which are implemented simple and efficiently with the help of the Bouncy Castle Crypto library.

You can also create message authentication hashes (HMAC) using the ```HMACHashGenerators``` class.

```c#
// Gets the HMAC SHA2-512 hash of the text "my text"
string hashedText = HMACHashGenerators.HMACSHA2_512("my text");
```

### PBKDF2 Password Hashing

The Hope.Security library implements a very simple way of hashing passwords using PBKDF2 hashing. It is all driven through one class: ```PBKDF2PasswordHashing```. Every time a new ```PBKDF2PasswordHashing``` instance is initialized, it uses an instance of ```PBKDF2Engine``` as the primary password hashing driver. 

See the following code.

```c#
// Initializes a new PBKDF2PasswordHashing instance with a Blake2b-512 hashing engine.
PBKDF2PasswordHashing blake2PasswordHashing = new PBKDF2PasswordHashing(new Blake2b_512_Engine());

// Gets the password hash of the password.
string passwordHash = blake2PasswordHashing.GetSaltedPasswordHash("password123");

// Checks if the password is correct.
// A different instance of PBKDF2PasswordHashing can be used as long as the same algorithm is used.
bool isCorrectPassword = blake2PasswordHashing.VerifyPassword("password123", passwordHash);
```

There are also many overloaded methods which allow for custom hashing iterations, salt size, and hash size.

See the following code.

```c#
// Initializes a new PBKDF2PasswordHashing instance with a SHA3-512 hashing engine.
PBKDF2PasswordHashing sha3PasswordHashing = new PBKDF2PasswordHashing(new SHA3_512_Engine());

// Gets the password has of the password, with an iteration count of 2500, salt size of 256, and hash size of 512.
string passwordHash = sha3PasswordHashing.GetSaltedPasswordHash("password123", 2500, 256, 512);

// Password must be verified with the same iteration count, salt size, and hash size.
bool isCorrectPassword = sha3PasswordHashing.VerifyPassword("password123", passwordHash, 2500, 256, 512);
```

See the [Hope.Security.Tests](https://github.com/HopeWallet/Hope.Security/tree/master/Hope.Security/Hope.Security.Tests) folder for more usage examples.

Many different engines are included to allow for many different scenarios. Some engines are faster than others, while being less secure, and vice versa. Play around with the engines to see what suits your needs best. The default iteration count is 50000, which is generally considered very secure. 

It is recommended that you use a minimum iteration count of 10000, salt size of 64, and hash size of 128. Once again, these values all affect the speed and security of the algorithm. If you can afford to use higher iteration counts and better algorithms (like Blake2 or SHA3) then it is highly recommended.

## Contributing

Contributions are always welcome! Whether it has to do with code refactoring, feature addition, or bugs - all are appreciated!

Create an [issue](https://github.com/HopeWallet/Hope.Security/issues) and create pull requests, and they will all be taken a look at!

## Final Words

This is a library of utility classes that were created for use in the Hope Ethereum wallet. This library won't likely get udated too much unless there are any glaring issues anywhere that haven't been discovered. If you encounter any problems, post an issue and support will gladly be provided!
