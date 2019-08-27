#include "fuzz.h"
#include "gki_int.h"

#define MODULE_NAME "NCI Fuzzing:"

enum {
  SUB_TYPE_DUMMY,

  SUB_TYPE_MAX
};

static void resp_cback(tNFC_RESPONSE_EVT event, tNFC_RESPONSE* p_data) {
  FUZZLOG(MODULE_NAME "event=0x%02x, p_data=%p", event, p_data);
}

static void nfc_vs_cback(tNFC_VS_EVT event, uint16_t len, uint8_t* data) {
  FUZZLOG(MODULE_NAME "event=0x%02x, data=%p", event,
          BytesToHex(data, len).c_str());
}

extern void hal_inject_event(uint8_t hal_evt, tHAL_NFC_STATUS status);
extern bool hal_inject_data(const uint8_t* p_data, uint16_t data_len);
extern tHAL_NFC_ENTRY* get_hal_func_entries();

extern uint8_t nci_snd_core_reset(uint8_t reset_type);
extern void GKI_shutdown();

extern tGKI_CB gki_cb;
static bool Fuzz_Init(Fuzz_Context& /*ctx*/) {
  GKI_init();
  gki_cb.os.thread_id[NFC_TASK] = pthread_self();

  NFC_Init(get_hal_func_entries());
  NFC_Enable(resp_cback);

  NFC_RegVSCback(true, nfc_vs_cback);

  nfc_set_state(NFC_STATE_CORE_INIT);
  nci_snd_core_reset(NCI_RESET_TYPE_RESET_CFG);
  return true;
}

static void Fuzz_Run(Fuzz_Context& ctx) {
  for (auto it = ctx.Data.cbegin(); it != ctx.Data.cend(); ++it) {
    hal_inject_data(it->data(), it->size());
  }
  GKI_shutdown();
}

void Nci_FixPackets(uint8_t /*SubType*/, std::vector<bytes_t>& /*Packets*/) {}

void Nci_Fuzz(uint8_t SubType, const std::vector<bytes_t>& Packets) {
  Fuzz_Context ctx(SubType % SUB_TYPE_MAX, Packets);
  if (Fuzz_Init(ctx)) {
    Fuzz_Run(ctx);
  }
}
