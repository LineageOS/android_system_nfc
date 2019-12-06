#include "fuzz.h"

extern void Nci_FixPackets(uint8_t SubType, std::vector<bytes_t>& Packets);
extern void Nci_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets);

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

  uint8_t FuzzType = Data[0];
  Nci_FixPackets(FuzzType, Packets);

  Size = PackPackets(Packets, Data + 1, MaxSize - 1);
  return Size + 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  const char* argv[] = {"nfc_nci_fuzzer"};
  base::CommandLine::Init(1, argv);
  logging::SetLogItems(false, false, false, false);

  // first byte is the type and command
  if (Size > 0) {
    uint8_t FuzzType = Data[0];
    auto Packets = UnpackPackets(Data + 1, Size - 1);

    Nci_Fuzz(FuzzType, Packets);
  }
  return 0;
}
