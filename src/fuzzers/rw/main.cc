#include "fuzz.h"

extern void Type1_FixPackets(uint8_t SubType, std::vector<bytes_t>& Packets);
extern void Type2_FixPackets(uint8_t SubType, std::vector<bytes_t>& Packets);
extern void Type3_FixPackets(uint8_t SubType, std::vector<bytes_t>& Packets);
extern void Type4_FixPackets(uint8_t SubType, std::vector<bytes_t>& Packets);
extern void Type5_FixPackets(uint8_t SubType, std::vector<bytes_t>& Packets);
extern void Mfc_FixPackets(uint8_t SubType, std::vector<bytes_t>& Packets);

extern void Type1_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets);
extern void Type2_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets);
extern void Type3_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets);
extern void Type4_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets);
extern void Type5_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets);
extern void Mfc_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets);

static std::vector<bytes_t> UnpackPackets(const uint8_t* Data, size_t Size) {
  std::vector<bytes_t> result;
  while (Size > 0) {
    auto s = *Data++;
    Size--;

    if (s > Size) {
      s = Size;
    }

    if (s > 5) {
      result.push_back(bytes_t(Data, Data + s));
    }

    Size -= s;
    Data += s;
  }

  return result;
}

static size_t PackPackets(const std::vector<bytes_t>& Packets, uint8_t* Data,
                          size_t MaxSize) {
  size_t TotalSize = 0;
  for (auto it = Packets.cbegin(); MaxSize > 0 && it != Packets.cend(); ++it) {
    auto s = it->size();
    if (s == 0) {
      // skip all empty packets
      continue;
    }

    if (s > MaxSize - 1) {
      s = MaxSize - 1;
    }
    *Data++ = (uint8_t)s;
    MaxSize--;

    memcpy(Data, it->data(), s);
    MaxSize -= s;

    TotalSize += (s + 1);
  }

  return TotalSize;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data, size_t Size,
                                          size_t MaxSize, uint Seed) {
  // One byte is required at mimimium for a fuzz input
  if (Size == 0) {
    Size = 1;
  }

  auto Packets = UnpackPackets(Data + 1, Size - 1);
  auto odd = Seed % 100;
  if (odd < 10) {
    // mutate tag type/command
    Data[0] = Seed & 0xFF;
  } else if (odd < 20 || Packets.size() == 0) {
    // insert a new packet
    auto len = Seed & 0xFF;
    if (Packets.size() > 0) {
      auto pos = Seed % Packets.size();
      Packets.insert(Packets.begin() + pos, bytes_t(len, 0xFF));
    } else {
      Packets.push_back(bytes_t(len, 0xFF));
    }
  } else if (odd < 30 && Packets.size() > 1) {
    // drop a packet
    auto pos = Seed % Packets.size();
    Packets.erase(Packets.begin() + pos);
  } else if (Packets.size() > 0) {
    // mutate a packet, maximium length 255
    auto pos = Seed % Packets.size();
    auto& p = Packets[pos];

    auto size = p.size();
    p.resize(0xFF);
    size = LLVMFuzzerMutate(p.data(), size, 0xFF);
    p.resize(size);
  }

  uint8_t CtrlByte = Data[0];
  uint8_t FuzzType = (CtrlByte >> 5) % Fuzz_TypeMax;
  uint8_t FuzzSubType = CtrlByte & 0x1F;

  switch (FuzzType) {
    case Fuzz_Type1:
      Type1_FixPackets(FuzzSubType, Packets);
      break;

    case Fuzz_Type2:
      Type2_FixPackets(FuzzSubType, Packets);
      break;

    case Fuzz_Type3:
      Type3_FixPackets(FuzzSubType, Packets);
      break;

    case Fuzz_Type4:
      Type4_FixPackets(FuzzSubType, Packets);
      break;
    case Fuzz_Type5:
      Type5_FixPackets(FuzzSubType, Packets);
      break;
    case Fuzz_Mfc:
      Mfc_FixPackets(FuzzSubType, Packets);
      break;

    default:
      FUZZLOG("Unknown fuzz type %hhu", FuzzType);
      break;
  }

  Size = PackPackets(Packets, Data + 1, MaxSize - 1);
  return Size + 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  const char* argv[] = {"nfc_rw_fuzzer"};
  base::CommandLine::Init(1, argv);
  logging::SetLogItems(false, false, false, false);

  // first byte is the type and command
  if (Size > 0) {
    uint8_t FuzzType = (Data[0] >> 5) % Fuzz_TypeMax;
    uint8_t FuzzSubType = Data[0] & 0x1F;
    auto Packets = UnpackPackets(Data + 1, Size - 1);

    FUZZLOG("Fuzzing Type%u tag", (uint)(FuzzType + 1));

    switch (FuzzType) {
      case Fuzz_Type1:
        Type1_Fuzz(FuzzSubType, Packets);
        break;

      case Fuzz_Type2:
        Type2_Fuzz(FuzzSubType, Packets);
        break;

      case Fuzz_Type3:
        Type3_Fuzz(FuzzSubType, Packets);
        break;

      case Fuzz_Type4:
        Type4_Fuzz(FuzzSubType, Packets);
        break;
      case Fuzz_Type5:
        Type5_Fuzz(FuzzSubType, Packets);
        break;
      case Fuzz_Mfc:
        Mfc_Fuzz(FuzzSubType, Packets);
        break;

      default:
        FUZZLOG("Unknown fuzz type: %hhu", FuzzType);
        break;
    }
  }

  if (__gcov_flush) {
    __gcov_flush();
  }
  return 0;
}
