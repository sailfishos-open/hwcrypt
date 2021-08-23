// Copyright 2015 The Android Open Source Project
//
// Copyright 2021 Rinigus
// Changes introduced as a part of hwcrypt development.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <sstream>

#include <base/command_line.h>
#include <hardware/keymaster_defs.h>
#include <keystore/keystore_client_impl.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include "hwcrypt.pb.h"

using base::CommandLine;
using namespace keystore;
using namespace std;

// AES encrytion
const uint32_t kAESKeySize = 256;      // bits

// Key generation by signing
#define SIGNKEYGEN_RSA_KEY_SIZE 2048
#define SIGNKEYGEN_RSA_KEY_SIZE_BYTES (SIGNKEYGEN_RSA_KEY_SIZE / 8)
#define SIGNKEYGEN_RSA_EXPONENT 0x10001


std::unique_ptr<KeystoreClient> CreateKeystoreInstance() {
  return std::unique_ptr<KeystoreClient>(static_cast<KeystoreClient*>(new keystore::KeystoreClientImpl));
}

void PrintTags(const AuthorizationSet& parameters, bool verbose) {
  for (auto iter = parameters.begin(); iter != parameters.end(); ++iter) {
    auto tag_str = toString(iter->tag);
    cout << " - " << tag_str;
    if (verbose) cout << ": " << toString(*iter);
    cout << "\n";
  }
}

void PrintKeyCharacteristics(const AuthorizationSet& hardware_enforced_characteristics,
			     const AuthorizationSet& software_enforced_characteristics,
			     bool verbose = false) {
  cout << "Hardware:\n";
  PrintTags(hardware_enforced_characteristics, verbose);
  cout << "\nSoftware:\n";
  PrintTags(software_enforced_characteristics, verbose);
}

int GetCharacteristics(const std::string& name, bool verbose=false) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  AuthorizationSet hardware_enforced_characteristics;
  AuthorizationSet software_enforced_characteristics;
  auto result = keystore->getKeyCharacteristics(name, &hardware_enforced_characteristics,
						&software_enforced_characteristics);
  if (result.isOk())
    PrintKeyCharacteristics(hardware_enforced_characteristics,
			    software_enforced_characteristics,
			    verbose);
  else
    cerr << "GetCharacteristics failed with error code " << result.getErrorCode() << "\n";
  return result.getErrorCode();
}

int List(const std::string& prefix) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  std::vector<std::string> key_list;
  if (!keystore->listKeys(prefix, &key_list)) {
    cerr << "ListKeys failed.\n";
    return 1;
  }
  cout << "Keys:\n";
  for (const auto& key_name : key_list)
    cout << " - " << key_name << "\n";
  return 0;
}

int DeleteKey(const std::string& name) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  auto result = keystore->deleteKey(name);
  if (!result.isOk())
    cerr << "Delete key failed with error code " << result.getErrorCode() << "\n";
  return result.getErrorCode();
}

///////////////////////////////////////////
// Misc helper functions

std::string hidlVec2String(const hidl_vec<uint8_t>& value) {
    return std::string(reinterpret_cast<const std::string::value_type*>(&value[0]), value.size());
}

bool ReadStdin(std::string &input) {
  // based on https://stackoverflow.com/a/39758021/11848012
  // by https://stackoverflow.com/users/3807729/galik
  const std::size_t INIT_BUFFER_SIZE = 1024;

  // Looks like cannot reopen in Android
  //std::freopen(nullptr, "rb", stdin);

  // if(std::ferror(stdin)) {
  //   cerr << "Error while reopening stdin in binary mode\n";
  //   return false;
  // }

  std::size_t len;
  std::array<char, INIT_BUFFER_SIZE> buf;

  // use std::fread and remember to only use as many bytes as are returned
  // according to len
  while((len = std::fread(buf.data(), sizeof(buf[0]), buf.size(), stdin)) > 0)
    {
      // whoopsie
      if(std::ferror(stdin) && !std::feof(stdin)) {
	cerr << "Error while reading stdin\n";
	return false;
      }

      // use {buf.data(), buf.data() + len} here
      input.insert(input.end(), buf.data(), buf.data() + len); // append to vector
    }

  return true;
}

///////////////////////////////////
// Support for encryption

bool verifyEncryptionKeyAttributes(const std::string& key_name,
				   bool* verified) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  AuthorizationSet hardware_enforced_characteristics;
  AuthorizationSet software_enforced_characteristics;
  auto result = keystore->getKeyCharacteristics(key_name, &hardware_enforced_characteristics,
						&software_enforced_characteristics);
  if (!result.isOk()) {
    cerr << "Failed to query encryption key: " << result.getErrorCode() << "\n";
    return false;
  }

  *verified = true;
  auto algorithm = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_ALGORITHM),
			    software_enforced_characteristics.GetTagValue(TAG_ALGORITHM));
  if (!algorithm.isOk() || algorithm.value() != Algorithm::AES) {
    cerr << "Found encryption key with invalid algorithm.\n";
    *verified = false;
  }
  auto key_size = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_KEY_SIZE),
			   software_enforced_characteristics.GetTagValue(TAG_KEY_SIZE));
  if (!key_size.isOk() || key_size.value() != kAESKeySize) {
    cerr << "Found encryption key with invalid size.\n";
    *verified = false;
  }
  auto block_mode = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_BLOCK_MODE),
			     software_enforced_characteristics.GetTagValue(TAG_BLOCK_MODE));
  if (!block_mode.isOk() || block_mode.value() != BlockMode::CBC) {
    cerr << "Found encryption key with invalid block mode.\n";
    *verified = false;
  }
  auto padding_mode = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_PADDING),
			       software_enforced_characteristics.GetTagValue(TAG_PADDING));
  if (!padding_mode.isOk() || padding_mode.value() != PaddingMode::PKCS7) {
    cerr << "Found encryption key with invalid padding mode.\n";
    *verified = false;
  }
  return true;
}

int GenerateEncryptionKey(const std::string& name, int32_t flags) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  AuthorizationSetBuilder params;
  params.AesEncryptionKey(kAESKeySize)
    .Padding(PaddingMode::PKCS7)
    .Authorization(TAG_BLOCK_MODE, BlockMode::CBC)
    .Authorization(TAG_NO_AUTH_REQUIRED);
  AuthorizationSet hardware_enforced_characteristics;
  AuthorizationSet software_enforced_characteristics;

  auto result = keystore->generateKey(name, params, flags, &hardware_enforced_characteristics,
				      &software_enforced_characteristics);
  if (result.isOk())
    PrintKeyCharacteristics(hardware_enforced_characteristics,
			    software_enforced_characteristics);
  else
    cerr << "Generate key failed with error code " << result.getErrorCode() << "\n";

  if (hardware_enforced_characteristics.size() == 0) {
    cerr << "Generated key is not hardware backed. Deleting it\n";
    DeleteKey(name);
    return -1;
  }

  bool verified = true;
  if (!verifyEncryptionKeyAttributes(name, &verified) ||
      !verified) {
    cerr << "Generated key failed verification, deleting\n";
    DeleteKey(name);
    return -1;
  }

  return result.getErrorCode();
}

bool EncryptOrDecryptOnce(bool encrypt,
			  const std::string& key_name,
			  const std::string& input_data,
			  std::string &output_data) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  AuthorizationSetBuilder params;
  params.Padding(PaddingMode::PKCS7);
  params.Authorization(TAG_BLOCK_MODE, BlockMode::CBC);
  AuthorizationSet output_params;
  uint64_t handle;

  output_data.clear();

  // help vars
  AuthorizationSet empty_params;
  size_t num_input_bytes_consumed;
  AuthorizationSet ignored_params;
  std::string buf_in;
  std::string buf_out;

  if (encrypt) buf_in = input_data;
  else {
    EncryptedPlainData protobuf;
    if (!protobuf.ParseFromString(input_data)) {
      cerr << "Decrypt: Failed to parse EncryptedPlainData protobuf.\n";
      return false;
    }

    params.Authorization(TAG_NONCE, protobuf.init_vector().data(),
			 protobuf.init_vector().size());
    buf_in = protobuf.encrypted_data();
  }

  // start encryption
  auto result = keystore->beginOperation(encrypt ? KeyPurpose::ENCRYPT : KeyPurpose::DECRYPT,
					 key_name, params,
					 &output_params, &handle);
  if (!result.isOk()) {
    cerr << "EncryptOrDecrypt BeginOperation failed: " << result.getErrorCode() << "\n";
    return false;
  }

  // encryption or decryption loop
  while (buf_in.size() > 0) {
    result = keystore->updateOperation(handle, empty_params, buf_in, &num_input_bytes_consumed,
				       &ignored_params, &buf_out);
    if (!result.isOk()) {
      cerr << "EncryptOrDecrypt UpdateOperation failed: " << result.getErrorCode() << "\n";
      return false;
    }
    output_data += buf_out;
    buf_in = buf_in.substr(num_input_bytes_consumed);
    buf_out.clear();
  }

  // finish
  result =
	keystore->finishOperation(handle, empty_params,
				  std::string(), /* signature_to_verify */
				  &ignored_params, &output_data);
  if (!result.isOk()) {
    cerr << "EncryptOrDecrypt FinishOperation failed: " << result.getErrorCode() << "\n";
    return false;
  }

  if (encrypt) {
    auto init_vector_blob = output_params.GetTagValue(TAG_NONCE);
    if (!init_vector_blob.isOk()) {
      cerr << "Encrypt: Missing initialization vector.\n";
      return false;
    }
    std::string init_vector = hidlVec2String(init_vector_blob.value());
    std::string encrypted_data;
    EncryptedPlainData protobuf;
    protobuf.set_init_vector(init_vector);
    protobuf.set_encrypted_data(output_data);
    if (!protobuf.SerializeToString(&encrypted_data)) {
      cerr << "Failed to serialize encrypted data to string\n";
      return false;
    }
    output_data = encrypted_data;
  }

  return true;
}

int Encrypt(const std::string& key_name)
{
  bool verified;
  if (!verifyEncryptionKeyAttributes(key_name, &verified) ||
      !verified) {
    cerr << "Encryption key failed verification\n";
    return -1;
  }

  std::string data;
  std::string encrypted_data;

  if (!ReadStdin(data)) return -1;

  if (!EncryptOrDecryptOnce(true, key_name, data, encrypted_data)) return 1;

  cout << encrypted_data;
  return 0;
}

int Decrypt(const std::string& key_name)
{
  bool verified;
  if (!verifyEncryptionKeyAttributes(key_name, &verified) ||
      !verified) {
    cerr << "Encryption key failed verification\n";
    return -1;
  }

  std::string output_data;
  std::string encrypted_data;

  if (!ReadStdin(encrypted_data)) return -1;
  if (!EncryptOrDecryptOnce(false, key_name, encrypted_data, output_data)) return 1;

  cout << output_data;
  return 0;
}

/////////////////////////////////////////
// Key generation through signing
//
// Specific encryption procedures used to generate encryption key from
// user-provided password. Approach is based on Android Full Disk
// Encryption (cryptfs.cpp) approach with some simplifications.


bool verifySignKeyGenKeyAttributes(const std::string& key_name,
				   bool* verified) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  AuthorizationSet hardware_enforced_characteristics;
  AuthorizationSet software_enforced_characteristics;
  auto result = keystore->getKeyCharacteristics(key_name, &hardware_enforced_characteristics,
						&software_enforced_characteristics);
  if (!result.isOk()) {
    cerr << "Failed to query encryption key: " << result.getErrorCode() << "\n";
    return false;
  }

  *verified = true;
  auto algorithm = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_ALGORITHM),
			    software_enforced_characteristics.GetTagValue(TAG_ALGORITHM));
  if (!algorithm.isOk() || algorithm.value() != Algorithm::RSA) {
    cerr << "Found encryption key with invalid algorithm.\n";
    *verified = false;
  }
  auto key_size = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_KEY_SIZE),
			   software_enforced_characteristics.GetTagValue(TAG_KEY_SIZE));
  if (!key_size.isOk() || key_size.value() != SIGNKEYGEN_RSA_KEY_SIZE) {
    cerr << "Found encryption key with invalid size.\n";
    *verified = false;
  }
  auto block_mode = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_DIGEST),
			     software_enforced_characteristics.GetTagValue(TAG_DIGEST));
  if (!block_mode.isOk() || block_mode.value() != Digest::NONE) {
    cerr << "Found encryption key with invalid block mode.\n";
    *verified = false;
  }
  auto padding_mode = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_PADDING),
			       software_enforced_characteristics.GetTagValue(TAG_PADDING));
  if (!padding_mode.isOk() || padding_mode.value() != PaddingMode::NONE) {
    cerr << "Found encryption key with invalid padding mode.\n";
    *verified = false;
  }
  return true;
}


int GenerateSignKeyGenHardwareKey(const std::string& name, int32_t flags, int seconds_between_tries) {
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  AuthorizationSetBuilder params;
  params.RsaSigningKey(SIGNKEYGEN_RSA_KEY_SIZE, SIGNKEYGEN_RSA_EXPONENT)
    .NoDigestOrPadding()
    .Authorization(TAG_NO_AUTH_REQUIRED)
    .Authorization(TAG_MIN_SECONDS_BETWEEN_OPS, seconds_between_tries);

  AuthorizationSet hardware_enforced_characteristics;
  AuthorizationSet software_enforced_characteristics;

  auto result = keystore->generateKey(name, params, flags, &hardware_enforced_characteristics,
				      &software_enforced_characteristics);
  if (result.isOk())
    PrintKeyCharacteristics(hardware_enforced_characteristics,
			    software_enforced_characteristics);
  else
    cerr << "Generate signature key failed with error code " << result.getErrorCode() << "\n";

  if (hardware_enforced_characteristics.size() == 0) {
    cerr << "Generated key is not hardware backed. Deleting it\n";
    DeleteKey(name);
    return -1;
  }

  bool verified = true;
  if (!verifySignKeyGenKeyAttributes(name, &verified) ||
      !verified) {
    cerr << "Generated signature key failed verification, deleting\n";
    DeleteKey(name);
    return -1;
  }

  return result.getErrorCode();
}

int SignKeyGen(const std::string& key_name)
{
  bool verified;
  if (!verifySignKeyGenKeyAttributes(key_name, &verified) ||
      !verified) {
    cerr << "Encryption key failed verification\n";
    return -1;
  }

  std::string data;
  std::string output_data;

  if (!ReadStdin(data)) return -1;

  // encryption works only for smaller datasets
  if (data.size() > SIGNKEYGEN_RSA_KEY_SIZE_BYTES-1) {
    cerr << "Input data too large for RSA signing\n";
    return -1;
  }
  
  // note from cryptfs.cpp:
  // To sign a message with RSA, the message must satisfy two
  // constraints:
  //
  // 1. The message, when interpreted as a big-endian numeric value, must
  //    be strictly less than the public modulus of the RSA key.  Note
  //    that because the most significant bit of the public modulus is
  //    guaranteed to be 1 (else it's an (n-1)-bit key, not an n-bit
  //    key), an n-bit message with most significant bit 0 always
  //    satisfies this requirement.
  //
  // 2. The message must have the same length in bits as the public
  //    modulus of the RSA key.  This requirement isn't mathematically
  //    necessary, but is necessary to ensure consistency in
  //    implementations.
  
  std::string buf_in;

  // same padding as in cryptfs.cpp:
  buf_in = std::string(1, 0) + data;
  if (buf_in.size() < SIGNKEYGEN_RSA_KEY_SIZE_BYTES)
    buf_in += std::string(SIGNKEYGEN_RSA_KEY_SIZE_BYTES - buf_in.size(), 0);

  ///////////////////////////////////
  // signing with RSA
  std::unique_ptr<KeystoreClient> keystore = CreateKeystoreInstance();
  AuthorizationSetBuilder params;
  params.NoDigestOrPadding();
  AuthorizationSet output_params;
  uint64_t handle;

  output_data.clear();

  // help vars
  AuthorizationSet empty_params;
  size_t num_input_bytes_consumed;
  AuthorizationSet ignored_params;
  std::string buf_out;
  KeyStoreNativeReturnCode result;
  
  // start operation
  while (true) {
    result = keystore->beginOperation(KeyPurpose::SIGN,
				      key_name, params,
				      &output_params, &handle);
    if (result.isOk())
      break;

    if (result == ErrorCode::KEY_RATE_LIMIT_EXCEEDED) {
      sleep(1);
    } else {
      // some other error
      cerr << "EncryptOrDecrypt BeginOperation failed: " << result.getErrorCode() << "\n";
      return -2;
    }
  }

  // data loop
  while (buf_in.size() > 0) {
    result = keystore->updateOperation(handle, empty_params, buf_in, &num_input_bytes_consumed,
				       &ignored_params, &buf_out);
    if (!result.isOk()) {
      cerr << "EncryptOrDecrypt UpdateOperation failed: " << result.getErrorCode() << "\n";
      return false;
    }
    output_data += buf_out;
    buf_in = buf_in.substr(num_input_bytes_consumed);
    buf_out.clear();
  }

  // finish
  result =
	keystore->finishOperation(handle, empty_params,
				  std::string(), /* signature_to_verify */
				  &ignored_params, &output_data);
  if (!result.isOk()) {
    cerr << "EncryptOrDecrypt FinishOperation failed: " << result.getErrorCode() << "\n";
    return false;
  }

  cout << output_data;
  return 0;
}



/////////////////////////////////////////
// Main and help
void PrintHelp(const string &prog) {
  cout << "Usage: " << prog << " command [arguments]\n\n"
       << "Commands: \n\n"
       << "  Generic commands:\n"
       << "          get-chars --name=<key_name> [-verbose]\n"
       << "          delete --name=<key_name>\n"
       << "          list [--prefix=<key_name_prefix>]\n\n"
       << "  Encryption and decryption commands:\n" 
       << "          generate-enc --name=<key_name> [--strongbox]\n"
       << "          [en|de]crypt --name=<key_name>\n\n"
       << "  Commands for key generation through signing:\n" 
       << "          generate-signkg --name=<key_name> [--time-between-tries=SECONDS] [--strongbox]\n"
       << "          signkg --name=<key_name>\n\n"
       << "For encryption, decryption, and key generation through signing, input and output are from stdin"
       << "and stdout, respectively.\n";
}

int main(int argc, char** argv) {
  CommandLine::Init(argc, argv);
  CommandLine* command_line = CommandLine::ForCurrentProcess();
  CommandLine::StringVector args = command_line->GetArgs();

  android::ProcessState::self()->startThreadPool();

  if (args.empty()) {
    PrintHelp(argv[0]);
    return 0;
  }

  int seconds_between_tries = 1;
  if (command_line->HasSwitch("time-between-tries")) {
    std::string ntxt = command_line->GetSwitchValueASCII("time-between-tries");
    stringstream s(ntxt);
    s >> seconds_between_tries;
  }

  if (args[0] == "get-chars") {
    return GetCharacteristics(command_line->GetSwitchValueASCII("name"),
			      command_line->HasSwitch("verbose"));
  } else if (args[0] == "delete") {
    return DeleteKey(command_line->GetSwitchValueASCII("name"));
  } else if (args[0] == "list") {
    return List(command_line->GetSwitchValueASCII("prefix"));
  } else if (args[0] == "generate-enc") {
    return GenerateEncryptionKey(command_line->GetSwitchValueASCII("name"),
				 command_line->HasSwitch("strongbox") ? KEYSTORE_FLAG_STRONGBOX : KEYSTORE_FLAG_NONE);
  } else if (args[0] == "encrypt") {
    return Encrypt(command_line->GetSwitchValueASCII("name"));
  } else if (args[0] == "decrypt") {
    return Decrypt(command_line->GetSwitchValueASCII("name"));
  } else if (args[0] == "generate-signkg") {
    return GenerateSignKeyGenHardwareKey(command_line->GetSwitchValueASCII("name"),
					 command_line->HasSwitch("strongbox") ? KEYSTORE_FLAG_STRONGBOX : KEYSTORE_FLAG_NONE,
					 seconds_between_tries);
  } else if (args[0] == "signkg") {
    return SignKeyGen(command_line->GetSwitchValueASCII("name"));
  }

  PrintHelp(argv[0]);
  return 0;
}
