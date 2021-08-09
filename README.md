# Hardware based encryption for Hybris based systems

`hwcrypt` tool allows to encrypt/decrypt files and use for key
generation through signing. Tool is targeting Hybris systems and
relies of Android stack for hardware based encryption. Tool is based
on `system/security/keystore/keystore_cli_v2.cpp`,
`system/vold/cryptfs.cpp` and codes used by them.

For encryption, decryption, and signing, `hwcrypt` takes input data
from standard input and outputs result through standard output.

When compared to `keystore_cli_v2` tool, `hwcrypt` can correctly
encrypt larger files as well. It seems that `keystore_cli_v2` encrypts
only one buffer (~16K when tested on one device) while `hwcrypt` would
loop through the full input. In addition to encryption,
`keystore_cli_v2` will also add authentication signature allowing it
to verify data on decryption. In contrast, `hwcrypt` does encryption
only.

Note that `hwcrypt` operations will succeed only if the used key has
hardware backing. Here, hardware backing is separate secure element
(sa Strongbox) or TEE. It should not fallback to software-only
solution provided by Android.


## Compilation

Add this repository to Android sources and compile using

In HADK:

```Shell
cd $ANDROID_ROOT
git clone https://github.com/rinigus/hwcrypt.git hybris/mw/hwcrypt
source build/envsetup.sh
export USE_CCACHE=1
lunch aosp_$DEVICE-user (or appropriate name)
make hwcrypt
```

Copy files for packaging:
```
hybris/mw/hwcrypt/rpm/copy-hal.sh
```

In SDK:
```
cd $ANDROID_ROOT
rpm/dhd/helpers/build_packages.sh --build=hybris/mw/hwcrypt --spec=rpm/droid-hwcrypt.spec --do-not-install
```

## Usage

`hwcrypt` allows to create new keys, list them, list their properties,
as well as encrypt/decrypt or sign data using these keys.

It is using the same syntax as `keystore_cli_v2`:
```
hwcrypt COMMAND [ARGUMENTS]
```

Almost all commands require key name as an argument given by
`--name=KEYNAME`.

### Generic commands

- `list`: List keys defined in the device

- `delete --name=KEY`: delete key with the name KEY

- `get-chars --name=KEY [--verbose]`: list key characteristics by
  splitting them into hardware- and software-backed properties. When
  verbose, full underlying information structure is printed. Note that
  as the information structure is implemented as C union, only one
  field of the union is used based on structure tag.


### Encrypting and decrypting data

- `generate-enc --name=KEY [--strongbox]`: generate hardware backed
  key with a unique name, optionally using Strongbox. If Secure
  Element backing is requested but not available, command will fail.

- `encrypt --name=KEY`: Encrypt text or binary as in
  - `cat Test | hwcrypt encrypt --name=testkey > encrypted.blob`

- `decrypt --name=KEY`: Decrypt data as in
  - `hwcrypt decrypt --name=testkey < encrypted.blob`


### Key generation through signing

To use hardware backed encryption key as a part of deterministic key
generator, `hwcrypt` signs input data in it's raw form with the
minimum padding. The approach is based on part of the key generation
scheme used by Android for [disk
encryption](https://source.android.com/security/encryption/full-disk#storing_the_encrypted_key). Signing is performed by RSA key.

- `generate-signkg --name=KEY [--time-between-tries=SECONDS]
  [--strongbox]`: Generates RSA key that can be used for signing
  data. Key usage is limited as one use per period of time given by
  `--time-between-tries=SECONDS` which is set to 1 second by
  default. While creating the key, note whether
  `MIN_SECONDS_BETWEEN_OPS` property is hardware backed. If it is,
  brute force attacks on key generation will be limited to the given
  tries per second frequency.

- `signkg --name=KEY`: sign input data with the specified key.

As used by Android, signed data is padded by one byte with zero value
on the left and as many bytes with zero value on the right to match
key size - 256 bytes. Implementation limits maximal data allowed to be
signed to 255 bytes. However, as main usage is targeting 32 byte keys
signing, it is not a limitation. Output is always 256 bytes that can
be processed further by scrypt or similar to reduce resulting key
size.

Example usage:

```Shell
> ./hwcrypt generate-signkg --name=testkg --time-between-tries=10
Hardware:
 - PURPOSE
 - PURPOSE
 - DIGEST
 - PADDING
 - ALGORITHM
 - KEY_SIZE
 - RSA_PUBLIC_EXPONENT
 - BLOB_USAGE_REQUIREMENTS
 - MIN_SECONDS_BETWEEN_OPS
 - NO_AUTH_REQUIRED
 - ORIGIN
 - 0x700002bf
 - OS_VERSION
 - OS_PATCHLEVEL

Software:
 - CREATION_DATETIME
```

Notice that most of the key properties are implemented in hardware, as
required. The creation time is expected to be software backed.


Encrypting test message:

```
echo -n "Test" | ./hwcrypt signkg --name=testkg | hexdump -c -v
0000000  \f   H   b 342 212 330 263 213 311   <   D 026   Y   = 027   Z
0000010 241 024 226 246   Z   3 262 251   ` 343   Z 030 273 254 322 272
0000020 214 300 363   H 254   ?     310 364 252 277   P 203 363 307   4
0000030 374 311   < 326   P   h 232   9  \a   l 024 365 022   3 033 235
0000040 372   ; 242 236 311 244 352 323   v 313   P   3   x 204 231 373
0000050   9   w 024 374   & 016 216 323 027   O 327   i   9   )   y   n
0000060 333 251 362   p 216 214   l 341 223 250 037 356 340   q 274   r
0000070 337 256 345   7       v 263 365 236  \n 361 004   B 235 346 321
0000080 252 216   Q 203   ]   C 005 002   r   / 330 211 275   R   H 365
0000090   B   }   a   3 211   F 223 341   * 246 274   ( 334 320   5 217
00000a0 006   Z 314   ! 254 032 222   ; 026 210   H   r 333   x 264 211
00000b0 350 343   x 201 254 364   `   M   U   d 321 226   \  \r 377 376
00000c0   K   Z   , 337 237 221   x   i   = 271   I   -  \0 231   ` 345
00000d0   i 301  \v   O 310 236   H   ) 026 364   :   w 317 237 323 356
00000e0 266 362 234   w 210   , 236   "   ' 216 351 354 025 303   j   -
00000f0   Z 217 357 257 032 366 375   ~ 214 237 233   Z 306 356 215 315
0000100
```

Notice that using other key, result is different
```
echo -n "Test" | ./hwcrypt signkg --name=testkg2 | hexdump -c -v
0000000   h 311 003 220   T 222   o 375 221 352  \a 301 223 216   -   ^
0000010   % 244   o 377 211  \t   s   9 200 024 331 354   U 341   q   ^
0000020   ) 227   }   { 346 372 364   c 256 214 333 264  \t 311   X 236
0000030   S 361 360   1 347 247   6 366 311 260   6 333 245 233   I   f
0000040 337 330 222 203  \n   g   A   _ 245  \v 204   o   T   /   f 212
0000050 331 356 246   C 374   h   x 342   $   Y   4 364 373 330 362   q
0000060   A 242   R 356 266   * 023 214   >   . 205 337   W   Y   w 204
0000070 341   F 326   &   T   J 246   = 006   f 252   &   + 315 340   p
0000080   v   @ 234 221 374 221 202 312  \f   X   8 001  \a 356   L 332
0000090 355 034   3 377   R   m  \v   / 251   i   R 352 334 245 247   @
00000a0 360   _ 211 361   a   g 220   J 352   }   1 321 223 265   b 364
00000b0   g 207   v 205 250 311  \b 331 036 224 357 366 311 365   c 353
00000c0 272 274   0   $ 302   P 224   3 335 034 231 266   %   N 274   U
00000d0 257 352 263 336 353   G   t 275   H 205   \   $   |   p  \r 373
00000e0 243 252   m  \0   b 203   A 302   j 244 212 354  \n 212 326 336
00000f0 336   )   ] 302 203   %   7 374 342   u   Z   Z   q 266   o 225
0000100
```
