#include <aidl/android/hardware/security/keymint/Algorithm.h>
#include <aidl/android/hardware/security/keymint/Digest.h>
#include <aidl/android/hardware/security/keymint/KeyCharacteristics.h>
#include <aidl/android/hardware/security/keymint/KeyFormat.h>
#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <aidl/android/hardware/security/keymint/KeyParameterValue.h>
#include <aidl/android/hardware/security/keymint/KeyPurpose.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <aidl/android/system/keystore2/Domain.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/KeyDescriptor.h>
#include <aidl/android/system/keystore2/KeyMetadata.h>
#include <aidl/android/system/keystore2/ResponseCode.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <keymint_support/key_param_output.h>

#include <fstream>
#include <gflags/gflags.h>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "error.h"
#include "hwcrypt.pb.h"

using namespace aidl::android::system::keystore2;
using namespace aidl::android::hardware::security::keymint;

const size_t CHUNK_SIZE = 512; // using very conservative size

// encryption parameters
const int ENCRYPTION_MAC_LENGTH = 128;

// get services
std::shared_ptr<IKeystoreService> getKeystoreService() {
  ndk::SpAIBinder binder(AServiceManager_getService("android.system.keystore2.IKeystoreService/default"));
  if (!binder.get()) {
    std::cerr << "Failed to get Keystore2 service." << std::endl;
    return nullptr;
  }

  std::shared_ptr<IKeystoreService> service = IKeystoreService::fromBinder(binder);
  if (!service) {
    std::cerr << "Failed to cast Keystore2 service binder." << std::endl;
    return nullptr;
  }

  return service;
}

std::shared_ptr<IKeystoreSecurityLevel> getSecurityLevel(std::shared_ptr<IKeystoreService> service = nullptr) {
  if (!service)
    service = getKeystoreService();

  if (!service)
    return nullptr;

  std::shared_ptr<IKeystoreSecurityLevel> security_level;
  auto status = service->getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT, &security_level);
  if (!status.isOk()) {
    std::cerr << "Failed to get security level: " << status.getMessage() << std::endl;
    return nullptr;
  }

  return security_level;
}

KeyDescriptor getKeyDescriptor(const std::string &key_name) {
  KeyDescriptor descriptor = {
      .domain = Domain::APP,
      .nspace = 0,
      .alias = key_name,
  };

  return descriptor;
}

// handle I/O streams

bool readStdin(std::vector<uint8_t> &input) {
  // based on https://stackoverflow.com/a/39758021/11848012
  // by https://stackoverflow.com/users/3807729/galik
  const size_t INIT_BUFFER_SIZE = 1024;

  size_t len;
  std::array<char, INIT_BUFFER_SIZE> buf;

  // use std::fread and remember to only use as many bytes as are returned
  // according to len
  while ((len = std::fread(buf.data(), sizeof(buf[0]), buf.size(), stdin)) > 0) {
    // whoopsie
    if (std::ferror(stdin) && !std::feof(stdin)) {
      std::cerr << "Error while reading stdin\n";
      return false;
    }

    // use {buf.data(), buf.data() + len} here
    input.insert(input.end(), buf.data(), buf.data() + len); // append to vector
  }

  return true;
}

void print(const std::vector<uint8_t> &data) {
  std::string output;
  output.insert(output.end(), data.begin(), data.end());
  std::cout << output;
}

// commands: provide information regarding keys

std::string toString(const KeyMetadata &metadata) {
  std::ostringstream ss;
  ss << "  Security Level: " << toString(metadata.keySecurityLevel) << std::endl;

  std::map<SecurityLevel, std::vector<KeyParameter>> grouped;

  for (const auto &param : metadata.authorizations) {
    grouped[param.securityLevel].push_back(param.keyParameter);
  }

  for (const auto &[secLevel, params] : grouped) {
    ss << "  + " << toString(secLevel) << ":\n";
    for (const auto &keyParam : params) {
      ss << "    - " << keyParam << '\n';
    }
  }

  return ss.str();
}

int getCharacteristics(const std::string &key_name) {
  auto service = getKeystoreService();
  if (!service)
    return 1;

  KeyDescriptor descriptor = getKeyDescriptor(key_name);

  KeyEntryResponse key_entry_response;
  auto ker_status = service->getKeyEntry(descriptor, &key_entry_response);
  if (!ker_status.isOk()) {
    std::cout << "Key not found" << "\n";
    return 1;
  }

  auto metadata = key_entry_response.metadata;

  std::cout << "Key: " << key_name << "\n";
  std::cout << "  Domain: " << toString(descriptor.domain) << "\n";
  std::cout << "  Namespace: " << descriptor.nspace << "\n";
  std::cout << toString(metadata) << std::endl;
  return 0;
}

// NB! returns 0 if there is a key and non-zero otherwise
int hasKey(const std::string &key_name) {
  auto service = getKeystoreService();
  if (!service)
    return 1;

  KeyDescriptor descriptor = getKeyDescriptor(key_name);

  KeyEntryResponse key_entry_response;
  auto ker_status = service->getKeyEntry(descriptor, &key_entry_response);
  if (!ker_status.isOk()) {
    std::cout << "Key " << key_name << " not found" << "\n";
    return 1;
  }

  std::cout << "Key " << key_name << " found\n";
  return 0;
}

int listKeys(const std::string &prefix = "", bool verbose = false) {
  auto service = getKeystoreService();
  if (!service)
    return 1;

  // List keys for the current application domain
  std::vector<KeyDescriptor> key_descriptors;
  auto status = service->listEntries(Domain::APP, 0, &key_descriptors);

  if (!status.isOk())
    return Error() << "Failed to list keys: " << status.getMessage();

  // Filter and display keys
  bool found_keys = false;
  for (const auto &descriptor : key_descriptors) {
    const std::string alias = descriptor.alias.value_or("");

    // Apply prefix filter if specified
    if (!prefix.empty() && alias.find(prefix) != 0) {
      continue;
    }

    found_keys = true;

    if (verbose) {
      // Verbose output - show key characteristics
      std::cout << "Key: " << alias << "\n";
      std::cout << "  Domain: " << toString(descriptor.domain) << "\n";
      std::cout << "  Namespace: " << descriptor.nspace << "\n";

      KeyEntryResponse key_entry_response;
      auto ker_status = service->getKeyEntry(descriptor, &key_entry_response);
      if (!ker_status.isOk())
        std::cout << "Key: " << alias << ": No key entry response, skipping detailed information" << "\n";
      else
        std::cout << toString(key_entry_response.metadata) << std::endl;
    } else
      std::cout << alias << std::endl;
  }

  if (!found_keys) {
    if (prefix.empty()) {
      std::cout << "No keys found." << std::endl;
    } else {
      std::cout << "No keys found with prefix: " << prefix << std::endl;
    }
  }

  return 0;
}

// Signing

int generate_signkg(const std::string &key_name, int timeout_seconds) {
  auto security_level = getSecurityLevel();
  if (!security_level)
    return 1;

  KeyDescriptor keyDesc = getKeyDescriptor(key_name);

  std::vector<KeyParameter> params = {
      {.tag = Tag::ALGORITHM, .value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::RSA)},
      {.tag = Tag::KEY_SIZE, .value = KeyParameterValue::make<KeyParameterValue::integer>(2048)},
      {.tag = Tag::RSA_PUBLIC_EXPONENT, .value = KeyParameterValue::make<KeyParameterValue::longInteger>(65537)},
      {.tag = Tag::PURPOSE, .value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN)},
      {.tag = Tag::DIGEST, .value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256)},
      {.tag = Tag::PADDING,
       .value = KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::RSA_PKCS1_1_5_SIGN)},
      {.tag = Tag::NO_AUTH_REQUIRED, .value = KeyParameterValue::make<KeyParameterValue::boolValue>(true)},
      {.tag = Tag::MIN_SECONDS_BETWEEN_OPS,
       .value = KeyParameterValue::make<KeyParameterValue::integer>(timeout_seconds)},
  };

  KeyMetadata metadata;
  auto status = security_level->generateKey(keyDesc, {}, // attestation key
                                            params,
                                            0,  // flags
                                            {}, // entropy
                                            &metadata);
  if (!status.isOk())
    return Error() << "Key generation failed: " << status;

  std::cout << "Key for signing generated: " << key_name << std::endl;
  std::cout << toString(metadata) << std::endl;
  return 0;
}

int signkg(const std::string &key_name) {
  auto security_level = getSecurityLevel();
  if (!security_level)
    return 1;

  // Read input
  std::vector<uint8_t> input;
  if (!readStdin(input))
    return Error() << "Failed to read from stdin.";

  // Prepare for signing
  std::optional<std::vector<uint8_t>> signature;
  KeyDescriptor keyDesc = getKeyDescriptor(key_name);

  std::vector<KeyParameter> params = {
      {.tag = Tag::PURPOSE, .value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN)},
      {.tag = Tag::DIGEST, .value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256)},
      {.tag = Tag::PADDING,
       .value = KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::RSA_PKCS1_1_5_SIGN)},
  };
  CreateOperationResponse opResponse;

  auto status = security_level->createOperation(keyDesc, params, false, &opResponse);
  if (!status.isOk())
    return Error() << "Failed to create keystore signing operation: " << status;
  auto operation = opResponse.iOperation;

  // push all data into operation with chunks
  for (size_t i = 0; i < input.size(); i += CHUNK_SIZE) {
    size_t chunk_size = std::min(CHUNK_SIZE, input.size() - i);
    std::vector<uint8_t> chunk(input.begin() + i, input.begin() + i + chunk_size);

    std::optional<std::vector<uint8_t>> output;
    status = operation->update(chunk, &output);
    if (!status.isOk()) {
      operation->abort();
      return Error() << "Failed to call keystore update operation:" << status;
    }
  }

  // Sign
  status = operation->finish({}, {}, &signature);
  if (!status.isOk())
    return Error() << "Failed to call keystore finish operation:" << status;

  if (!signature.has_value())
    return Error() << "Didn't receive a signature from keystore finish operation.";

  print(signature.value());
  return 0;
}

// encryption

int generate_enc(const std::string &key_name) {
  auto security_level = getSecurityLevel();
  if (!security_level)
    return 1;

  KeyDescriptor keyDesc = getKeyDescriptor(key_name);

  std::vector<KeyParameter> params = {
      {.tag = Tag::ALGORITHM, .value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::AES)},
      {.tag = Tag::KEY_SIZE, .value = KeyParameterValue::make<KeyParameterValue::integer>(256)},
      {.tag = Tag::PURPOSE, .value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::ENCRYPT)},
      {.tag = Tag::PURPOSE, .value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::DECRYPT)},
      {.tag = Tag::BLOCK_MODE, .value = KeyParameterValue::make<KeyParameterValue::blockMode>(BlockMode::GCM)},
      {.tag = Tag::PADDING, .value = KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::NONE)},
      {.tag = Tag::MIN_MAC_LENGTH, .value = KeyParameterValue::make<KeyParameterValue::integer>(ENCRYPTION_MAC_LENGTH)},
      {.tag = Tag::NO_AUTH_REQUIRED, .value = KeyParameterValue::make<KeyParameterValue::boolValue>(true)},
  };

  KeyMetadata metadata;
  auto status = security_level->generateKey(keyDesc, {}, // attestation key
                                            params,
                                            0,  // flags
                                            {}, // entropy
                                            &metadata);
  if (!status.isOk())
    return Error() << "Key generation failed: " << status;

  std::cout << "Encryption key generated: " << key_name << std::endl;
  std::cout << toString(metadata) << std::endl;
  return 0;
}

int encrypt(const std::string &key_name) {
  auto security_level = getSecurityLevel();
  if (!security_level)
    return 1;

  // Read input
  std::vector<uint8_t> input;
  if (!readStdin(input))
    return Error() << "Failed to read from stdin.";

  KeyDescriptor keyDesc = getKeyDescriptor(key_name);

  std::vector<KeyParameter> params = {
      {.tag = Tag::PURPOSE, .value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::ENCRYPT)},
      {.tag = Tag::BLOCK_MODE, .value = KeyParameterValue::make<KeyParameterValue::blockMode>(BlockMode::GCM)},
      {.tag = Tag::PADDING, .value = KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::NONE)},
      {.tag = Tag::MAC_LENGTH, .value = KeyParameterValue::make<KeyParameterValue::integer>(ENCRYPTION_MAC_LENGTH)},
  };

  CreateOperationResponse opResponse;
  auto status = security_level->createOperation(keyDesc, params, false, &opResponse);
  if (!status.isOk())
    return Error() << "Failed to create keystore encryption operation: " << status;

  auto operation = opResponse.iOperation;
  std::vector<uint8_t> encrypted_output;

  // Process input in chunks
  for (size_t i = 0; i < input.size(); i += CHUNK_SIZE) {
    size_t chunk_size = std::min(CHUNK_SIZE, input.size() - i);
    std::vector<uint8_t> chunk(input.begin() + i, input.begin() + i + chunk_size);

    std::optional<std::vector<uint8_t>> output;
    status = operation->update(chunk, &output);
    if (!status.isOk()) {
      std::optional<std::vector<uint8_t>> dummy;
      operation->abort();
      return Error() << "Failed to call keystore update operation: " << status;
    }

    if (output.has_value()) {
      encrypted_output.insert(encrypted_output.end(), output->begin(), output->end());
    }
  }

  // Finish the operation to get the final encrypted data + auth tag
  std::optional<std::vector<uint8_t>> final_output;
  status = operation->finish({}, {}, &final_output);
  if (!status.isOk())
    return Error() << "Failed to call keystore finish operation: " << status;

  if (final_output.has_value()) {
    encrypted_output.insert(encrypted_output.end(), final_output->begin(), final_output->end());
  }

  // get init vector (nonce)
  std::vector<uint8_t> init_vector;
  {
    auto params = opResponse.parameters;
    for (auto &p : params->keyParameter) {
      if (auto iv = authorizationValue(TAG_NONCE, p)) {
        init_vector = std::move(iv->get());
        break;
      }
    }
    if (init_vector.empty())
      return Error() << "Encryption operation did not return an init_vector.";
  }

  hwcrypt::EncryptedPlainData protobuf;
  protobuf.set_init_vector(init_vector.data(), init_vector.size());
  protobuf.set_encrypted_data(encrypted_output.data(), encrypted_output.size());
  if (!protobuf.SerializeToOstream(&std::cout))
    return Error() << "Failed to serialize the result";
  return 0;
}

int decrypt(const std::string &key_name) {
  auto security_level = getSecurityLevel();
  if (!security_level)
    return 1;

  hwcrypt::EncryptedPlainData protobuf;
  if (!protobuf.ParseFromIstream(&std::cin))
    return Error() << "Failed to read from stdin.";

  std::vector<uint8_t> init_vector(protobuf.init_vector().begin(), protobuf.init_vector().end());
  std::string input = protobuf.encrypted_data();

  KeyDescriptor keyDesc = getKeyDescriptor(key_name);

  std::vector<KeyParameter> params = {
      {.tag = Tag::PURPOSE, .value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::DECRYPT)},
      {.tag = Tag::BLOCK_MODE, .value = KeyParameterValue::make<KeyParameterValue::blockMode>(BlockMode::GCM)},
      {.tag = Tag::PADDING, .value = KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::NONE)},
      {.tag = Tag::MAC_LENGTH, .value = KeyParameterValue::make<KeyParameterValue::integer>(ENCRYPTION_MAC_LENGTH)},
      {.tag = Tag::NONCE, .value = KeyParameterValue::make<KeyParameterValue::blob>(init_vector)},
  };

  CreateOperationResponse opResponse;
  auto status = security_level->createOperation(keyDesc, params, false, &opResponse);
  if (!status.isOk())
    return Error() << "Failed to create keystore decryption operation: " << status;

  auto operation = opResponse.iOperation;
  std::vector<uint8_t> decrypted_output;

  // Process input in chunks
  for (size_t i = 0; i < input.size(); i += CHUNK_SIZE) {
    size_t chunk_size = std::min(CHUNK_SIZE, input.size() - i);
    std::vector<uint8_t> chunk(input.begin() + i, input.begin() + i + chunk_size);

    std::optional<std::vector<uint8_t>> output;
    status = operation->update(chunk, &output);
    if (!status.isOk()) {
      std::optional<std::vector<uint8_t>> dummy;
      operation->abort();
      return Error() << "Failed to call keystore update operation: " << status;
    }

    if (output.has_value()) {
      decrypted_output.insert(decrypted_output.end(), output->begin(), output->end());
    }
  }

  // Finish the operation - this will verify the auth tag and return final plaintext
  std::optional<std::vector<uint8_t>> final_output;
  status = operation->finish({}, {}, &final_output);
  if (!status.isOk())
    return Error() << "Failed to call keystore finish operation (authentication may have failed): " << status;

  if (final_output.has_value()) {
    decrypted_output.insert(decrypted_output.end(), final_output->begin(), final_output->end());
  }

  print(decrypted_output);
  return 0;
}

// key management
int deleteKey(const std::string &key_name) {
  auto service = getKeystoreService();
  if (!service)
    return 1;

  KeyDescriptor descriptor_alias = getKeyDescriptor(key_name);

  KeyEntryResponse key_entry_response;
  auto ker_status = service->getKeyEntry(descriptor_alias, &key_entry_response);
  if (!ker_status.isOk())
    return Error() << "Key " << key_name << " not found" << "\n";

  KeyDescriptor key = key_entry_response.metadata.key;
  auto del_status = service->deleteKey(key);
  if (!del_status.isOk())
    return Error() << "Key delete failed" << del_status << "\n";

  std::cout << "Key " << key_name << " deleted" << "\n";
  return 0;
}

// command line options and handling commands

DEFINE_string(name, "", "Key name for operations");
DEFINE_string(prefix, "", "Key name prefix for list command");
DEFINE_bool(verbose, false, "Enable verbose output");
DEFINE_int32(time_between_tries, 0, "Time between tries in seconds for generate-signkg");

enum class Command {
  UNKNOWN,
  GET_CHARS,
  DELETE,
  LIST,
  HASKEY,
  GENERATE_ENC,
  ENCRYPT,
  DECRYPT,
  GENERATE_SIGNKG,
  SIGNKG
};

Command parseCommand(const std::string &cmd) {
  if (cmd == "get-chars")
    return Command::GET_CHARS;
  if (cmd == "delete")
    return Command::DELETE;
  if (cmd == "list")
    return Command::LIST;
  if (cmd == "haskey")
    return Command::HASKEY;
  if (cmd == "generate-enc")
    return Command::GENERATE_ENC;
  if (cmd == "encrypt")
    return Command::ENCRYPT;
  if (cmd == "decrypt")
    return Command::DECRYPT;
  if (cmd == "generate-signkg")
    return Command::GENERATE_SIGNKG;
  if (cmd == "signkg")
    return Command::SIGNKG;
  return Command::UNKNOWN;
}

void printUsage(const char *prog) {
  std::cout << "Usage: " << prog << " command [arguments]\n\n"
            << "Commands: \n\n"
            << "  Generic commands:\n"
            << "          get-chars --name=<key_name> [--verbose]\n"
            << "          delete --name=<key_name>\n"
            << "          list [--prefix=<key_name_prefix>] [--verbose]\n\n"
            << "          haskey [--name=<key_name>]\n\n"
            << "  Encryption and decryption commands:\n"
            << "          generate-enc --name=<key_name>\n"
            << "          [en|de]crypt --name=<key_name>\n\n"
            << "  Commands for key generation through signing:\n"
            << "          generate-signkg --name=<key_name> "
               "[--time-between-tries=SECONDS]\n"
            << "          signkg --name=<key_name>\n\n"
            << "For encryption, decryption, and key generation through "
               "signing, input and output are from stdin "
            << "and stdout, respectively.\n\n"
            << "When checking for key existence with haskey command, "
               "application will have exit "
            << "code 0 if the key was found and non-zero otherwise.\n";
}

bool validateCommand(Command cmd, const char *prog) {
  switch (cmd) {
  case Command::LIST:
    break;
  case Command::UNKNOWN:
    std::cerr << "Error: Unknown command\n";
    printUsage(prog);
    return false;
  default:
    if (FLAGS_name.empty()) {
      std::cerr << "Error: --name is required for this command\n";
      return false;
    }
    break;
  }
  return true;
}

int executeCommand(Command cmd) {
  // init binder
  ABinderProcess_setThreadPoolMaxThreadCount(1);
  ABinderProcess_startThreadPool();

  // process the command
  switch (cmd) {
  case Command::GET_CHARS:
    return getCharacteristics(FLAGS_name);

  case Command::DELETE:
    return deleteKey(FLAGS_name);

  case Command::LIST:
    return listKeys(FLAGS_prefix, FLAGS_verbose);

  case Command::HASKEY:
    return hasKey(FLAGS_name);

  case Command::GENERATE_ENC:
    return generate_enc(FLAGS_name);

  case Command::ENCRYPT:
    return encrypt(FLAGS_name);

  case Command::DECRYPT:
    return decrypt(FLAGS_name);

  case Command::GENERATE_SIGNKG:
    return generate_signkg(FLAGS_name, FLAGS_time_between_tries);

  case Command::SIGNKG:
    return signkg(FLAGS_name);

  default:
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  // Set up gflags
  gflags::SetUsageMessage("Android CLI utility for key management and cryptographic operations");
  gflags::SetVersionString("1.0.0");

  gflags::ParseCommandLineFlags(&argc, &argv, true);

  // Check if we have at least one argument (the command)
  if (argc < 2) {
    printUsage(argv[0]);
    return 1;
  }

  // Parse the command
  std::string cmdStr = argv[1];
  Command cmd = parseCommand(cmdStr);

  // Validate command and its required parameters
  if (!validateCommand(cmd, argv[0])) {
    return 1;
  }

  // Execute the command
  int result = executeCommand(cmd);

  // Cleanup gflags
  gflags::ShutDownCommandLineFlags();

  return result;
}
