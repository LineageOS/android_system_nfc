#include "fuzz_cmn.h"

std::string BytesToHex(const uint8_t* data, size_t size) {
  std::string result = "{";
  if (data && size) {
    StringAppendF(&result, "0x%02X", data[0]);
    for (auto i = 1; i < size; i++) {
      StringAppendF(&result, ", 0x%02X", data[i]);
    }
  }
  result += "}";

  return result;
}

std::string BytesToHex(const bytes_t& data) {
  return BytesToHex(&data[0], data.size());
}

bytes_t FuzzSeqGen(size_t minLen, size_t maxLen) {
  bytes_t result;
  size_t len = (random() % (maxLen - minLen)) + minLen;
  for (auto i = 0; i < len; i++) {
    result.push_back(random() & 0xFF);
  }

  return result;
}
