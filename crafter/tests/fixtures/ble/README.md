# BLE Fixture Corpus

These fixtures are synthetic, deterministic DLT-256
`LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` frames for offline decode tests. Each
`.hex` file contains one full frame: BLE pseudo-header, advertising access
address, advertising-channel PDU, and three CRC octets.

The frames use the advertising access address `0x8e89bed6`, primary
advertising channels 37 through 39, LE 1M PHY metadata, and de-whitened PDU
bytes. Addresses are synthetic BLE random-static values under
`C2:00:5E:00:53:*`, and names are synthetic fixture markers:

- `adv_ind_flags_name.hex`: `ADV_IND`, AdvA `C2:00:5E:00:53:47`, Flags
  `0x06`, Complete Local Name `crafter-adv`.
- `adv_nonconn_ind_mfg_data.hex`: `ADV_NONCONN_IND`, AdvA
  `C2:00:5E:00:53:48`, Manufacturer Specific Data company ID `0xffff`,
  payload `01 02 03 04`.
- `scan_rsp_name.hex`: `SCAN_RSP`, AdvA `C2:00:5E:00:53:49`, Complete Local
  Name `crafter-scan`.
