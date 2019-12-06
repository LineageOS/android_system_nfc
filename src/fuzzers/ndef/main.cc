#include "fuzz_cmn.h"
#include "nfa_api.h"
#include "nfa_dm_int.h"

tNFA_DM_CB nfa_dm_cb = {};
bool ndef_handler_registered = false;

static void ndef_cback(tNFA_NDEF_EVT event, tNFA_NDEF_EVT_DATA* p_data) {
  if (event == NFA_NDEF_REGISTER_EVT) {
    ndef_handler_registered = (p_data->ndef_reg.status == NFC_STATUS_OK);
  } else if (event == NFA_NDEF_DATA_EVT) {
    FUZZLOG("ndef_data, start=%p, len=%d", p_data->ndef_data.p_data,
            p_data->ndef_data.len);

    uint16_t cs = 0;
    for (uint8_t* p = p_data->ndef_data.p_data;
         p < p_data->ndef_data.p_data + p_data->ndef_data.len; p++) {
      cs += *p;
    }

    FUZZLOG("ndef_data, checksum=%04X", cs);
  }
}

tNFA_DM_MSG reg_hdler = {.reg_ndef_hdlr = {
                             .tnf = NFA_TNF_DEFAULT,
                             .p_ndef_cback = ndef_cback,
                         }};

static bool init() {
  if (!ndef_handler_registered) {
    nfa_dm_ndef_reg_hdlr(&reg_hdler);
  }
  return ndef_handler_registered;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  const char* argv[] = {"nfc_ndef_fuzzer"};
  base::CommandLine::Init(1, argv);
  logging::SetLogItems(false, false, false, false);

  // first byte is the type and command
  if (!init()) {
    return 0;
  }

  nfa_dm_ndef_handle_message(NFA_STATUS_OK, const_cast<uint8_t*>(Data),
                             (uint32_t)Size);

  return 0;
}
