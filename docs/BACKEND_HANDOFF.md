# Backend Handoff — Pembagian Sisa Pekerjaan

Dokumen ini membagi sisa pekerjaan backend Assignment 1 antara **nopaalh (BE-1)** dan **Kamal (BE-2)**. Titik awalnya adalah commit `61d0b18`: auth, AES-128-CBC-HMAC buatan tangan, dan pipeline file AES dianggap selesai dan tidak diubah.

## 1. Keputusan yang sudah diambil

> Skenario dan model kepemilikan adalah **usulan BE**; perlu dikonfirmasi oleh seluruh tim (4 orang).

| Topik | Keputusan | Alasan singkat |
| --- | --- | --- |
| Skenario | Sistem internal rumah sakit untuk tenaga medis | Data kesehatan termasuk data pribadi **spesifik** (UU PDP Pasal 4 ayat 2); rekam medis elektronik juga diatur Permenkes 24/2022 |
| Pemilik data | Tenaga medis yang mengunggah; hanya dia yang dapat mendekripsi | Memenuhi syarat "only an authenticated user may get their own data back" tanpa RBAC; dijustifikasi sebagai *need-to-know / least privilege*. Query `user_id` yang ada tetap dipakai |
| Cipher | AES-128, **single DES**, RC4 — semua buatan tangan | Soal meminta DES, bukan 3DES. Implementasi manual diuji terhadap stdlib Go |
| Mode | AES-CBC (sudah ada), DES-CBC; CTR generik hanya untuk benchmark | Mode AES dan DES sama sehingga perbandingan mengukur biaya cipher, bukan biaya mode. CTR dipakai untuk analisis video (random access, paralel, tanpa padding) |
| RC4 | Nonce acak per file, buang 1536 byte awal keystream (RFC 4345), HMAC-SHA256 | Keystream yang dipakai ulang membocorkan `P1 ⊕ P2` (Stallings §8.4); byte awal RC4 bias; RC4 tidak punya integritas |
| Kunci | Satu master key `FILE_ENCRYPTION_KEY`, diturunkan per cipher dengan label HMAC | Mengikuti pola `deriveAESFileKeys`; tidak perlu env baru |
| Data terstruktur | Satu blob JSON per record, dienkripsi ×3 | Polanya sama dengan file; field terenkripsi memang tidak bisa di-query per field |
| Nama file | `File.OriginalName` ikut dienkripsi ×3 | Nama seperti `hasil_lab_budi_HIV.pdf` membocorkan data kesehatan |
| Ukuran video | Tetap in-memory; batas ditentukan dari hasil benchmark (placeholder 25 MiB) | Pipeline memuat seluruh file (puncak memori ±7× ukuran file dengan 3 cipher); streaming dicatat sebagai *future work* |

## 2. Pembagian

| Kode | Pekerjaan | PIC | Lokasi utama | Bergantung pada |
| --- | --- | --- | --- | --- |
| A | DES core (IP/FP, PC-1/PC-2, key schedule, E, 8 S-box, P, 16 ronde Feistel) | Kamal | `backend/utils/des.go` | — |
| B | RC4 core (KSA + PRGA, sesuai slide W5 23–24) | Kamal | `backend/utils/rc4.go` | — |
| C | Mode generik: CBC + PKCS7, CTR | Kamal | `backend/utils/modes.go` | — |
| D | Envelope file DES dan RC4 | Kamal | `backend/utils/des_file.go`, `rc4_file.go` | A, B, C |
| H | Benchmark dan analisis (mikro, makro, ciphertext) | Kamal | `backend/utils/*_bench_test.go`, skrip makro | D; makro juga E |
| E | Integrasi DES dan RC4 ke `FileService`, controller, model, docs | nopaalh | `services/`, `controllers/`, `models/`, `docs/` | kontrak D (§3) |
| F | `PatientRecord` terenkripsi ×3 + enkripsi `OriginalName` | nopaalh | `models/`, `repositories/`, `services/`, `controllers/` | kontrak D |
| G | Menaikkan batas upload untuk video | nopaalh | `services.MaxFileSize` | angka throughput dari H-mikro |

Urutan Kamal: A → B → C → D → H-mikro (kirim angka throughput untuk G) → H-makro (setelah E).
nopaalh bisa mengerjakan F dan G-struktur lebih dulu dengan kontrak §3, lalu E begitu D masuk.

## 3. Kontrak antar-BE

Kontrak ini dikunci sejak awal agar E dan F bisa dikerjakan paralel. Signature-nya identik dengan `EncryptAESFile`/`DecryptAESFile`:

```go
func EncryptDESFile(plaintext []byte, key [32]byte) ([]byte, error)
func DecryptDESFile(encrypted []byte, key [32]byte) ([]byte, error)
func EncryptRC4File(plaintext []byte, key [32]byte) ([]byte, error)
func DecryptRC4File(encrypted []byte, key [32]byte) ([]byte, error)
```

Perilakunya sama dengan AES: HMAC diverifikasi sebelum dekripsi, error tidak pernah mengembalikan plaintext parsial, dan `key` adalah master key 32 byte yang sama.

| Envelope | Format | Turunan kunci |
| --- | --- | --- |
| `DES1` | `"DES1" ‖ IV 8 B ‖ DES-CBC + PKCS7 (blok 8) ‖ HMAC-SHA256` | enc = `HMAC(master, "DES1/encryption")[:8]`, mac = `HMAC(master, "DES1/authentication")` |
| `RC41` | `"RC41" ‖ nonce 16 B ‖ RC4-drop1536 ‖ HMAC-SHA256` | enc = `HMAC(master, "RC41/encryption" ‖ nonce)[:16]`, mac = `HMAC(master, "RC41/authentication")` |

HMAC mencakup `magic ‖ IV/nonce ‖ ciphertext`, sama dengan `AES1`.

Saran untuk E (keputusan akhir di nopaalh): kolom timing `DES*/RC4*TimeNS` setara AES, dan pemilihan algoritma saat dekripsi lewat query, mis. `POST /api/files/:id/decrypt?algorithm=aes|des|rc4`.

## 4. Syarat analisis (dari slide W4 18–19)

Soal asli di slide menambahkan poin yang tidak ada di ringkasan tugas:

- Analisis perbedaan antar cipher dari **running time** dan **ciphertext yang dihasilkan**.
- **"Download the data multiple times and measure the running time!"**
- Program harus **bug-free** untuk nilai penuh.

Rencana H:

| Lapis | Cara | Menjawab |
| --- | --- | --- |
| Mikro | `go test -bench -count=10` + `benchstat`; file sampel nyata (scan KTP, PDF, DOCX, MP4) dan ukuran sintetis bertingkat; termasuk CBC vs CTR serta baseline `crypto/aes` dan `crypto/des` | Biaya murni cipher dan mode |
| Makro | Panggil endpoint dekripsi N=30× per file per algoritma; catat `X-Decryption-Time-Ns` dan latensi total | Instruksi "download multiple times" |
| Ciphertext | Overhead ukuran (padding/IV/MAC), entropi byte, plaintext sama → ciphertext berbeda, efek drop RC4 | "the resulting cipher text" |

Hasilnya diekspor ke CSV untuk grafik laporan.

## 5. Poin wajib untuk laporan

- **Weakest link:** setiap data disimpan dalam tiga salinan terenkripsi dari plaintext yang sama, jadi kerahasiaannya setara cipher terlemah. DES 56-bit sudah bisa di-brute-force sejak 1998 (EFF Deep Crack).
- **Implementasi, bukan algoritma:** cipher buatan tangan tidak dioptimasi (AES tanpa T-table, S-box dihitung ulang per operasi file). Selisih kecepatan harus dibaca dengan baseline stdlib di sampingnya.
- **Least privilege:** alasan hanya pengunggah yang dapat mendekripsi.
- **Klasifikasi UU PDP** field `PatientRecord`: umum (nama, jenis kelamin, NIK, tanggal lahir, alamat, telepon) vs spesifik/kesehatan (no. RM, no. BPJS, golongan darah, alergi, diagnosis).
- **Keterbatasan:** pencarian per field tidak didukung, video dibatasi ukuran (belum streaming), cipher buatan tangan tidak constant-time.

## 6. Keputusan terbuka

- Konfirmasi skenario dan model kepemilikan oleh seluruh tim.
- `User.Name` (data staf) saat ini plaintext. Default: tidak dienkripsi dan dijelaskan di laporan, karena mengubahnya menyentuh alur auth.
- Angka akhir batas upload video, menunggu H-mikro.
- `backend/.env.example` masih berisi `AES_KEY`, sedangkan `main.go` membaca `FILE_ENCRYPTION_KEY` (64 hex) dan `FILE_STORAGE_DIR`.

## 7. Aturan kerja

- Commit kecil dan sering dengan format `feat(scope): ...` / `test(scope): ...` / `docs(scope): ...`; riwayat commit ikut dinilai.
- Setiap cipher dan mode buatan tangan wajib diuji terhadap stdlib Go dan test vector resmi, mengikuti pola `utils/aes_file_test.go`.
- Fitur yang mengubah API wajib memperbarui `docs/API.md` / `docs/FILES.md`.
