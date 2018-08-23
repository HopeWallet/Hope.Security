# Hope.Security

Cross platform security library which implements secure PBKDF2 password hashing, symmetric encryption, and various other security principals.

## Installation

The required dlls for the Hope.Security library are located in the [Hope.Security releases](https://github.com/HopeWallet/Hope.Security/releases). Download the latest Hope.Security zip file and add all required dlls to your project references.

## Usage

The usage for the Hope.Security library are split up into several different sections. There is a section which implements Symmetric Encryption, another section which implements secure hashing of byte/string data, as well as secure PBKDF2 password hashing.

### Symmetric Encryption

### Data Hashing

### PBKDF2 Password Hashing

The usage for the PBKDF2.NET library is very simple. It is all driven through one class: ```PBKDF2PasswordHashing```. Every time a new ```PBKDF2PasswordHashing``` instance is initialized, it uses an instance of ```PBKDF2Engine``` as the primary password hashing driver. 

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

## Final Words

This is a library of utility classes that were created for use in the Hope Ethereum wallet. This library won't likely get udated too much unless there are any glaring issues anywhere that haven't been discovered. If you encounter any problems, post an issue and support will gladly be provided!
