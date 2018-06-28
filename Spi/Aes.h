const int Nr = 10;  // AES-128需要 10 轮加密
const int Nk = 4;   // Nk 表示输入密钥的 DWORD 个数
void Subbytes(BYTE mtx[4 * 4]);
void ShiftRows(BYTE mtx[4 * 4]);
void MixColumns(BYTE mtx[4 * 4]);
void AddRoundKey(BYTE mtx[4 * 4], DWORD k[4]);
void InvSubbytes(BYTE mtx[4 * 4]);
void InvShiftRows(BYTE mtx[4 * 4]);
void InvMixColumns(BYTE mtx[4 * 4]);
DWORD Word(BYTE k1, BYTE k2, BYTE k3, BYTE k4);
DWORD RotWord(DWORD rw);
DWORD SubWord(DWORD sw);
void KeyExpansion(BYTE  key[4 * Nk], DWORD w[4 * (Nr + 1)]);
void Encrypt(BYTE in[4 * 4], DWORD w[4 * (Nr + 1)]);
void Decrypt(BYTE in[4 * 4], DWORD w[4 * (Nr + 1)]);
void MasterEncrypt(DWORD  inW[44], USHORT random, BYTE out[4 * 4]);