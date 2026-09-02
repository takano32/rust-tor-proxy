# TASKS.md — 依存ゼロ Tor クライアント + SOCKS5 プロキシ 実装計画

対象読者: この計画をそのまま実装する AI エージェント(Opus 5 など)および人間の開発者。
このファイルは「何を・どの順で・どう確認しながら」作るかを定義する。仕様の詳細は
`spec.torproject.org` を正とし、本書には実装に必要な要点と落とし穴だけを書く。

---

## 0. 背景と決定事項

### 0.1 なぜ arti を捨てるのか(実測結果)

| 構成 | 依存クレート数 | 240MB cgroup 制限下のビルド | 備考 |
|---|---|---|---|
| 現 HEAD(arti-client 組み込み) | 554 | **不可**(syn が OOM で kill) | フルビルド 20 分、最終クレートの rustc RSS 596MB。起動直後に rustls の CryptoProvider 未設定で panic するため、そもそも動かない |
| 初期版 b79359b(依存 0、外部 tor の SOCKS5 に接続) | 0 | 成功(128MB 制限でも成功) | バイナリ 564KB |
| 純 Rust 4 万行クレート(winnow)単体 | 1 | 成功(160MB 制限でも成功) | 自前実装の規模の目安 |
| `openssl` クレート | 20 | 成功(240MB) | ただし syn を引き込むので不採用 |
| `rustls` / `rsa` クレート | — | **不可** | rustls 384MB、rsa 経由の zerocopy 391MB |

rustc は依存ゼロでも RSS 約 160MB を使うが、そのうち約 100MB は rustc 本体の共有ライブラリ
(ファイルバックのページ)で、メモリ逼迫時にカーネルが回収できる。したがって
**「依存ゼロ + libssl/libcrypto への手書き FFI」なら 128〜200MB 環境でも `cargo run` できる**。

### 0.2 決定事項

1. **外部クレートは使わない**(`[dependencies]` を空にする)。暗号と TLS はシステムの
   OpenSSL 3(`libssl.so.3` / `libcrypto.so.3`)へ `extern "C"` で直接リンクする。build.rs も不要。
2. **Listen は SOCKS5**(旧 HTTP プロキシは廃止)。`SERVER_PORT` 環境変数はそのまま使う。
3. **非同期ランタイムは使わない**。`std::thread` + ブロッキング I/O。
4. **Tor クライアント機能は最小**: microdesc 方式の通常クライアントのみ。
   Onion service、bridge、PT、ntor-v3、輻輳制御(cc)、パディング交渉は対象外。
5. `.cargo/config.toml` の `jobs = 1` は維持する。
6. `Cargo.lock` は依存ゼロなので 1 パッケージだけになる。

### 0.3 対象環境の前提

- Linux、メモリ 128〜240MB、swap の有無は問わない。
- `libssl.so.3` と `libcrypto.so.3` が存在すること(ヘッダは不要)。
  `ldconfig -p | grep -E 'libssl|libcrypto'` で確認する。
- Rust stable(1.96 で検証)。

---

## 1. ゴールと非ゴール

**ゴール**
- `SERVER_PORT=9050 cargo run --release` で SOCKS5 サーバが起動し、
  `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip` が
  `"IsTor":true` を返す。
- ビルドが `systemd-run --user --scope -p MemoryMax=200M -p MemorySwapMax=0 cargo build --release` で通る。
- 実行時 RSS が 60MB 未満(目標 30MB 台)。

**非ゴール**
- Tor Browser 相当の匿名性。ガード選択・経路重み付けは簡略化する(後述)。
- IPv6 のみの環境、onion サービス、bridge、DNS の RESOLVE セル。

---

## 2. アーキテクチャ

```
src/
  main.rs            起動、Config、SOCKS5 accept ループ(既存 config.rs を流用)
  socks5.rs          SOCKS5 サーバ(handshake → CONNECT → relay へ)
  relay.rs           双方向コピー(既存を流用、std::io ベース)
  ffi/
    mod.rs           unsafe extern "C" 宣言(libssl / libcrypto)
    tls.rs           SslStream: Read/Write を実装した安全ラッパ
    hash.rs          Sha1/Sha256 one-shot と running digest(EVP_MD_CTX)
    hmac.rs          HMAC-SHA256
    aes.rs           Aes128Ctr(連続キーストリーム)
    x25519.rs        鍵生成 + ECDH
    ed25519.rs       検証のみ
    rsa.rs           PKCS#1 v1.5 署名検証(DigestInfo なし)+ PEM/DER 読込
    rand.rs          RAND_bytes
  tor/
    cell.rs          固定長/可変長セルの encode/decode
    channel.rs       1 リレーへの TLS 接続 + リンクハンドシェイク + reader スレッド
    certs.rs         CERTS セルと Ed25519 証明書(cert-spec)のパース・検証
    ntor.rs          ntor ハンドシェイクと KDF-RFC5869
    circuit.rs       CREATE2/EXTEND2、onion 暗号層、RELAY セルの送受信、SENDME
    stream.rs        RELAY_BEGIN/DATA/END、ストリーム単位の Read/Write
    dir/
      fetch.rs       BEGIN_DIR 経由の HTTP GET
      consensus.rs   microdesc コンセンサスのパースと署名検証
      microdesc.rs   microdesc のパース
      authority.rs   ディレクトリ認証局の埋め込みリストと鍵証明書
      fallback.rs    フォールバックディレクトリの埋め込みリスト
      cache.rs       ディスクキャッシュ(state dir)
    path.rs          guard / middle / exit の選択
    client.rs        上記を束ねる TorClient(bootstrap, connect(host, port))
```

スレッドモデル:
- `channel`: 接続ごとに reader スレッド 1 本。受信セルを CircID で振り分け、
  各 circuit の `mpsc::Sender<Cell>` に渡す。書き込みは `Mutex<SslStream>` で直列化。
- `circuit`: 回路ごとに 1 スレッド(またはストリーム側からの呼び出しで駆動)。
  受信 RELAY セルを復号・認識し、StreamID ごとの `mpsc::Sender<Vec<u8>>` に配る。
- SOCKS5 接続ごとに 1 スレッド。`TorClient::connect` でストリームを得て `relay::bidirectional` を回す。

---

## 3. マイルストーン

各マイルストーンは「完了条件」を満たしたらコミットする。
コミット前に必ず §5 のメモリ検証コマンドを実行し、結果をコミットメッセージに書く。

### M0. 土台の整理

- [x] `git rm` で `src/http.rs`、`src/server.rs` を削除。`Cargo.toml` の `[dependencies]` を空にし、
      `async-std` / `arti-client` / `tor-rtcompat` / `futures-util` を消す。`cargo update` で lock を再生成。
- [x] `src/main.rs`、`src/config.rs`、`src/relay.rs` を b79359b 時点の同期版(std::io)に戻す。
      `git show b79359b:src/relay.rs` などで取得できる。
- [x] `Cargo.toml` に以下を追加(rustc のメモリを増やさない設定):
      ```toml
      [profile.release]
      debug = 0
      [profile.dev]
      debug = 0
      ```
- [x] README を SOCKS5 前提に書き換える(`--socks5-hostname` / `ALL_PROXY=socks5h://` の例)。
- 完了条件: `cargo build` が依存ゼロで通る(まだ何もしない main で可)。

### M1. OpenSSL FFI 層(`src/ffi/`)

- [x] `#[link(name = "ssl")]` と `#[link(name = "crypto")]` を付けた `extern "C"` ブロックを書く。
      必要な関数は §4 の一覧。型は `*mut c_void` で十分(opaque)。
- [x] `Drop` で必ず `*_free` を呼ぶ安全ラッパを作る。生ポインタを外に漏らさない。
- [x] `SslStream`:
  - `SSL_CTX_new(TLS_client_method())`、`SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, null)`
    (リレーの TLS 証明書は自己署名。真正性は CERTS セルで検証する)。
  - `SSL_set_fd` に `TcpStream::as_raw_fd()` を渡す。`TcpStream` は所有して drop 順を守る。
  - `SSL_connect` 後、`SSL_get1_peer_certificate` → `i2d_X509` で DER を取り、
    SHA-256 を保持する(CERTS 検証で使う)。
  - `std::io::Read` / `Write` を実装。`SSL_read` が 0 以下なら `SSL_get_error` で
    `SSL_ERROR_ZERO_RETURN`(=6) を EOF、それ以外をエラーにする。
  - read/write タイムアウトは `TcpStream::set_read_timeout` で入れる。
- [x] ハッシュ: `EVP_sha1()` / `EVP_sha256()` one-shot(`EVP_Digest`)と
      running digest(`EVP_MD_CTX_new` / `EVP_DigestInit_ex` / `EVP_DigestUpdate` /
      `EVP_MD_CTX_copy_ex` + `EVP_DigestFinal_ex` で「途中状態の値を取り出しつつ継続」)。
- [x] HMAC-SHA256: `HMAC()` one-shot。
- [x] AES-128-CTR: `EVP_CIPHER_CTX_new`、`EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), null, key, iv=全0)`、
      `EVP_EncryptUpdate` を繰り返す(キーストリームは呼び出しをまたいで連続する。
      復号も同じ EncryptUpdate でよい)。
- [x] X25519: `EVP_PKEY_keygen`(id `EVP_PKEY_X25519` = 1034)、
      `EVP_PKEY_get_raw_public_key`、`EVP_PKEY_new_raw_public_key`、
      `EVP_PKEY_derive_init` / `EVP_PKEY_derive_set_peer` / `EVP_PKEY_derive`。
- [x] Ed25519 検証: `EVP_PKEY_new_raw_public_key`(id `EVP_PKEY_ED25519` = 1087)、
      `EVP_DigestVerifyInit(ctx, null, null, null, pkey)`、`EVP_DigestVerify(ctx, sig, 64, msg, len)`。
- [x] RSA 検証: PEM `-----BEGIN RSA PUBLIC KEY-----`(PKCS#1 RSAPublicKey)を base64 デコードし、
      `d2i_PublicKey(EVP_PKEY_RSA=6, null, &ptr, len)` で EVP_PKEY 化。
      署名検証は **`EVP_PKEY_verify_recover`**(`EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING=1)`)
      で復元したバイト列と、自分で計算したダイジェストを**そのまま**比較する。
      Tor の署名は PKCS#1 v1.5 パディングだが **DigestInfo(OID)を含まない**ので
      `EVP_PKEY_verify` は使えない(dir-spec/netdoc.md「The signature does not include the algorithmIdentifier」)。
- [x] `RAND_bytes`。
- [x] 単体テスト: SHA-256("abc")、HMAC の RFC 4231 ベクタ、AES-128-CTR の NIST SP800-38A F.5.1、
      X25519 の RFC 7748 §6.1、Ed25519 の RFC 8032 §7.1 テスト 1。
- 完了条件: `cargo test` が通り、`-p MemoryMax=200M` でビルドが通る。

### M2. セルとリンクハンドシェイク(`cell.rs`, `certs.rs`, `channel.rs`)

- [x] セル形式(tor-spec/cell-packet-format.md):
  - 固定長: `CircID(4) | Command(1) | Payload(509)`。可変長: `CircID | Command(1) | Length(2) | Body`。
  - VERSIONS(7)と Command ≥ 128 が可変長。**VERSIONS 送受信時のみ CircID は 2 バイト**、
    リンク v4 以降に合意した後は 4 バイト。
- [x] ハンドシェイク手順(tor-spec/negotiating-channels.md):
  1. TLS 接続。
  2. VERSIONS を送る(本体は `00 03 00 04` = v3, v4。v5 はパディング交渉が絡むので送らない)。
  3. 相手の VERSIONS を受け、共通最大を選ぶ(v4 を期待)。
  4. CERTS(129)、AUTH_CHALLENGE(130)、NETINFO(8)を順に受ける。AUTH_CHALLENGE は読み捨ててよい
     (クライアントは認証しない)。
  5. NETINFO を返す: `TIME=00000000 | OTHERADDR(type 4, len 4, 相手 IPv4) | NMYADDR=0`。
     タイムスタンプ 0 とアドレス省略は仕様で推奨されている(フィンガープリント回避)。
- [x] CERTS の検証(negotiating-channels.md「Authenticating the responder」):
  - CertType 4(IDENTITY_V_SIGNING)がちょうど 1 つ。自己署名で、拡張 type 4
    (signed-with-ed25519-key)の 32 バイト鍵 = `KP_relayid_ed`。subject = `KP_relaysign_ed`。
  - CertType 5(SIGNING_V_TLS_CERT)がちょうど 1 つ。`KP_relaysign_ed` で署名され、
    subject(32 バイト)が **TLS ピア証明書 DER の SHA-256** と一致すること。
  - 両方とも署名が正しく、期限切れでないこと(EXPIRATION は epoch からの**時間**単位)。
  - `KP_relayid_ed` が、コンセンサス/microdesc から期待した Ed25519 識別子と一致すること。
- [x] Ed25519 証明書のバイナリ形式(cert-spec.md): `VERSION(1)=1 | CERT_TYPE(1) | EXPIRATION(4) |
      CERT_KEY_TYPE(1) | CERTIFIED_KEY(32) | N_EXT(1) | {ExtLen(2) ExtType(1) ExtFlags(1) ExtData}* | SIG(64)`。
      署名対象は SIG を除く全体。
- [x] reader スレッド: セルを読み、CircID 0 のもの(PADDING 0、VPADDING 128 など)は捨て、
      それ以外は登録済み circuit に転送。未知の CircID は捨てる。
- [x] 完了条件(結合テスト、要ネットワーク): フォールバックリレー 1 台に接続し、
      CERTS 検証まで成功したらログに Ed25519 識別子を出す。
      `cargo test -- --ignored` で実行できる形にする。

### M3. ntor と 1 ホップ回路(`ntor.rs`, `circuit.rs`)

- [x] ntor(tor-spec/create-created-cells.md):
  - `PROTOID = "ntor-curve25519-sha256-1"`、`t_mac = PROTOID|":mac"`、`t_key = PROTOID|":key_extract"`、
    `t_verify = PROTOID|":verify"`、`m_expand = PROTOID|":key_expand"`。
  - 送信 onion skin: `NODEID(20, リレーの RSA 識別子 SHA-1) | KEYID(32, ntor-onion-key B) | X(32)`。
  - 応答: `Y(32) | AUTH(32)`。
  - `secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID`
  - `KEY_SEED = HMAC_SHA256(key=t_key, secret_input)`、`verify = HMAC_SHA256(key=t_verify, secret_input)`
  - `auth_input = verify | ID | B | Y | X | PROTOID | "Server"`、
    `AUTH == HMAC_SHA256(key=t_mac, auth_input)` を定数時間比較で確認。
  - KDF-RFC5869(tor-spec/setting-circuit-keys.md): `K_1 = HMAC(KEY_SEED, m_expand|0x01)`、
    `K_(i+1) = HMAC(KEY_SEED, K_i|m_expand|INT8(i+1))`。先頭から
    `Df(20) | Db(20) | Kf(16) | Kb(16)` を取る(残りは捨てる)。
- [x] CREATE2(10): `HTYPE=0x0002 | HLEN=84 | HDATA`。CREATED2(11): `HLEN | HDATA`。
- [x] CircID: リンク v4 ではコネクションの開始側(=自分)が **MSB=1** の値を選ぶ。0 は禁止。
- [x] RELAY セル本体(509 バイト、tor-spec/relay-cells.md):
      `RelayCmd(1) | Recognized(2)=0 | StreamID(2) | Digest(4) | Length(2) | Data | Padding(0 埋め)`。
  - 送信: Digest を 0 にした 509 バイトで Df の running SHA-1 を更新し、その時点の
    ダイジェスト先頭 4 バイトを Digest に入れる。次に **hop N から hop 1 の順に** Kf で暗号化。
  - 受信: hop 1 の Kb で復号し、Recognized==0 かつ(Digest を 0 にして Db を更新した)
    ダイジェスト先頭 4 バイトが一致すれば認識。一致しなければ次 hop の Kb で続ける。
    **一致しなかった場合は Db の状態を巻き戻す**必要があるので、`EVP_MD_CTX_copy_ex` で
    コピーに対して試算し、一致したときだけ本体を更新する。
- [x] RELAY_EARLY(9): EXTEND2 は必ず RELAY_EARLY で送る。1 回路あたり最大 8 個。
- [x] DESTROY(4)受信で回路を閉じる。理由コードは tor-spec/tearing-down-circuits.md。
- [x] 完了条件: 1 ホップ回路で RELAY_BEGIN_DIR(13)→ CONNECTED(4)まで到達する
      (次の M4 と合わせて検証してよい)。

### M4. ディレクトリ取得と検証(`tor/dir/`)

- [x] 埋め込みデータ:
  - 認証局: https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/auth_dirs.inc
    から `nickname, orport, v3ident, IPv4:dirport, RSA 識別子` を Rust の `const` 配列に写す
    (2026-09 時点で 9 局 + bridge 認証局 Serge。Serge は `bridge` なので除外)。
  - フォールバック: 同 `fallback_dirs.inc`(291 件)。`ip orport id` の 3 つだけ使う。
    先頭 30〜50 件で十分。**取得元 URL とコミットハッシュをソースのコメントに残す**。
- [x] BEGIN_DIR 経由 HTTP: 1 ホップ回路 → RELAY_BEGIN_DIR(payload 空) → CONNECTED →
      `GET <path> HTTP/1.0\r\nHost: <ip>\r\n\r\n` を RELAY_DATA(最大 498 バイト/セル)で送り、
      レスポンスを END まで読む。`.z` は付けない(圧縮なし。zlib を FFI する場合は後回し)。
  - `/tor/status-vote/current/consensus-microdesc`(約 2.5MB)
  - `/tor/keys/fp/<FP1>+<FP2>+...`(認証局の鍵証明書。`/tor/keys/all` でも可)
  - `/tor/micro/d/<D1>-<D2>-...`(base64、`=` なし、`+`ではなく`-`区切り、1 回 92 件まで)
- [x] 鍵証明書(dir-spec/creating-key-certificates.md): `dir-key-certificate-version 3`、`fingerprint`、
      `dir-identity-key`、`dir-signing-key`、`dir-key-expires`、`dir-key-certification`。
      `fingerprint` が埋め込みの v3ident と一致し、`dir-key-certification` が
      identity key による SHA-1 署名(冒頭から `dir-key-certification\n` まで)として検証できること。
- [x] コンセンサス署名(dir-spec/consensus-formats.md): `directory-signature sha256 <identity> <signing-key-digest>`。
      ハッシュ対象は `network-status-version` の先頭から **`directory-signature ` の直後のスペースまで**
      (改行は含めない)。`sha256` 指定なら SHA-256、無指定なら SHA-1。
      **信頼する認証局の過半数**(9 局なら 5 以上)の有効な署名があれば受理する。
      `valid-until` を過ぎていれば再取得。
- [x] コンセンサスのパース(必要な行だけ): `r <nick> <id_b64> <date> <time> <ip> <orport> <dirport>`、
      `m <md_digest_b64>`、`s <flags>`、`w Bandwidth=<n>`、`p`(コンセンサス側の p は使わない)、
      `params`、`bandwidth-weights`、`valid-after/fresh-until/valid-until`。
      文字列は保持せず、`r` ごとに構造体(識別子 20B、md digest 32B、IPv4、port、flags bitset、bw u32)へ
      落として本文は捨てる(メモリ対策)。
- [x] microdesc(dir-spec/computing-microdescriptors.md): `onion-key`(無視可)、`ntor-onion-key <b64>`、
      `id ed25519 <b64>`、`p accept|reject <ports>`、`family`。ダイジェストは
      **`onion-key` 行の先頭から末尾まで**の SHA-256(コンセンサスの `m` と照合)。
- [x] ディスクキャッシュ: `$TOR_STATE_DIR`(既定 `./state`)に `consensus`、`certs`、
      `microdescs/<hex>`、`guard` を保存。起動時は有効期限内ならネットワークに行かない。
- [x] 完了条件: 署名検証済みのコンセンサスから、Guard/Exit の件数と `valid-until` をログ出力できる。

### M5. 3 ホップ回路と経路選択(`path.rs`, `circuit.rs` の EXTEND2)

- [x] EXTEND2(14)の payload: `NSPEC(1) | {LSTYPE(1) LSLEN(1) LSPEC}* | HTYPE(2)=2 | HLEN(2) | HDATA`。
      link specifier は **[00] IPv4(4+2)、[02] legacy id(20)、[03] Ed25519 id(32)** をこの順で。
      EXTENDED2(15)は CREATED2 と同じ `HLEN | HDATA`。
- [x] 経路選択(簡略版、path-spec 準拠は将来課題):
  - guard: flags に Guard, Running, Valid, Stable があるもの。1 台を選んで `state/guard` に永続化し、
    落ちるまで使い続ける(ガード固定は匿名性の基本)。
  - middle: Running, Valid。
  - exit: Exit, Running, Valid かつ microdesc の `p` が宛先ポートを許可。
  - 同一 /16、同一 family は同一回路に入れない。重みは `w Bandwidth` に比例(bandwidth-weights は
    初版では無視してよいが TODO コメントを残す)。
  - microdesc は **選んだ候補の分だけ**取得する(全 8000 件は取らない)。exit 候補は
    ポート別に 30 件程度をサンプリングして取得・キャッシュ。
- [x] 回路の再利用: 1 回路に複数ストリームを載せる。作成から 10 分または
      ストリームが失敗したら新しい回路を作る。回路作成の全体タイムアウトは 60 秒。
- [x] 完了条件: 3 ホップ回路で RELAY_BEGIN → CONNECTED が成功する。

### M6. ストリームとフロー制御(`stream.rs`)

- [x] RELAY_BEGIN(1): `"host:port\0"`(FLAGS は省略)。CONNECTED(4)、END(3、理由コードは
      tor-spec/closing-streams.md、空 payload は MISC 扱い)。
- [x] RELAY_DATA(2): 最大 498 バイト。
- [x] フロー制御(tor-spec/flow-control.md):
  - 回路レベル: deliver window 1000、100 受信ごとに SENDME(5, StreamID=0)。
    **version 1 形式**: `VERSION(1)=1 | DATA_LEN(2)=20 | DIGEST(20)`。DIGEST は
    「その SENDME を引き起こした(100 個目の)RELAY_DATA を処理した直後の Db running digest の値」。
    受信処理で 20 バイトのダイジェストを毎回控えておく。
  - ストリームレベル: window 500、50 受信ごとに SENDME(該当 StreamID)。
  - 送信側: package window(回路 1000、ストリーム 500)が 0 になったら相手の SENDME を待つ。
- [x] `TorStream`: `Read`/`Write` を実装し、`relay::bidirectional` にそのまま渡せるようにする。
- [x] 完了条件: 3 ホップ経由で `GET https://check.torproject.org/api/ip` の本文が取れ、
      100KB 超のダウンロード(SENDME が動く)が完走する。

### M7. SOCKS5 サーバ(`socks5.rs`, `main.rs`)

- [x] greeting: `05 NMETHODS METHODS` → `05 00`(認証なし)。`00` が無ければ `05 FF` で切断。
- [x] request: `05 01 00 ATYP ...`。ATYP=03(hostname)を主に扱う。ATYP=01(IPv4)は許可、
      ATYP=04(IPv6)は `05 08`(address type not supported)。CMD≠01 は `05 07`。
- [x] 応答: 成功 `05 00 00 01 00000000 0000`、失敗は Tor の END 理由を SOCKS の REP に写像
      (EXITPOLICY→02 not allowed、RESOLVEFAILED→04 host unreachable、CONNECTREFUSED→05、他→01)。
- [x] 接続ごとにスレッド。`SERVER_PORT` 必須は既存 `config.rs` のまま。
- [x] 完了条件: `curl --socks5-hostname 127.0.0.1:$SERVER_PORT https://check.torproject.org/api/ip` が
      `"IsTor":true`。`ALL_PROXY=socks5h://...` でも同じ。

### M8. 仕上げ

- [x] ログ: `TOR_LOG=debug|info|warn` 環境変数で制御(println ベースで十分)。
- [x] 実行時 RSS の計測を README に記載(`/proc/<pid>/status` の VmHWM)。
- [x] `cargo clippy -- -D warnings`、`cargo fmt`。
- [x] README: 使い方、制限事項(匿名性は本家に劣る、onion 非対応)、必要ライブラリ。

---

## 4. FFI 関数一覧(OpenSSL 3)

`libssl`:
`TLS_client_method`, `SSL_CTX_new`, `SSL_CTX_free`, `SSL_CTX_set_verify`, `SSL_new`, `SSL_free`,
`SSL_set_fd`, `SSL_connect`, `SSL_read`, `SSL_write`, `SSL_get_error`, `SSL_shutdown`,
`SSL_get1_peer_certificate`

`libcrypto`:
`X509_free`, `i2d_X509`, `OPENSSL_free`,
`EVP_sha1`, `EVP_sha256`, `EVP_Digest`, `EVP_MD_CTX_new`, `EVP_MD_CTX_free`, `EVP_DigestInit_ex`,
`EVP_DigestUpdate`, `EVP_DigestFinal_ex`, `EVP_MD_CTX_copy_ex`,
`HMAC`,
`EVP_aes_128_ctr`, `EVP_CIPHER_CTX_new`, `EVP_CIPHER_CTX_free`, `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`,
`EVP_PKEY_CTX_new_id`, `EVP_PKEY_CTX_new`, `EVP_PKEY_CTX_free`, `EVP_PKEY_keygen_init`, `EVP_PKEY_keygen`,
`EVP_PKEY_get_raw_public_key`, `EVP_PKEY_new_raw_public_key`, `EVP_PKEY_free`,
`EVP_PKEY_derive_init`, `EVP_PKEY_derive_set_peer`, `EVP_PKEY_derive`,
`EVP_DigestVerifyInit`, `EVP_DigestVerify`,
`d2i_PublicKey`, `EVP_PKEY_verify_recover_init`, `EVP_PKEY_verify_recover`, `EVP_PKEY_CTX_set_rsa_padding`,
`RAND_bytes`

定数: `SSL_VERIFY_NONE=0`, `SSL_ERROR_ZERO_RETURN=6`, `SSL_ERROR_WANT_READ=2`,
`EVP_PKEY_RSA=6`, `EVP_PKEY_X25519=1034`, `EVP_PKEY_ED25519=1087`, `RSA_PKCS1_PADDING=1`。

`EVP_PKEY_CTX_set_rsa_padding` は 3.x では実関数(1.1 ではマクロ)なので直接呼べる。
1.1 系しかない環境は対象外とする(`SSL_get1_peer_certificate` も 3.0 で追加された名前)。

---

## 5. 検証コマンド(各マイルストーンで実行)

```sh
# メモリ制限下でビルドが通ること(cgroup v2 + systemd ユーザセッションが必要)
systemd-run --user --scope -q -p MemoryMax=200M -p MemorySwapMax=0 cargo build --release -j1

# rustc ごとの最大 RSS を記録したい場合(ラッパ)
cat > /tmp/rustc-wrap.sh <<'EOF'
#!/bin/sh
name=""; prev=""
for a in "$@"; do [ "$prev" = "--crate-name" ] && name="$a"; prev="$a"; done
exec /usr/bin/time -f "%M KB %e s $name" -a -o "$RSS_LOG" "$@"
EOF
chmod +x /tmp/rustc-wrap.sh
RSS_LOG=/tmp/rss.log RUSTC_WRAPPER=/tmp/rustc-wrap.sh cargo build --release -j1 && sort -rn /tmp/rss.log | head

# 実行時メモリ
SERVER_PORT=9050 cargo run --release &
sleep 60; grep -E 'VmRSS|VmHWM' /proc/$!/status
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

---

## 5.5 実装状況(2026-09-02 完了)

M0〜M8 まで完了。`cargo test` 66 件、`cargo test -- --ignored` の実機テスト 4 件、
`cargo clippy --all-targets -- -D warnings` と `cargo fmt --check` がいずれも通る。
`MemoryMax=200M` でのリリースビルド成功、実行時 VmHWM 18.4MB(目標 60MB 未満)。
`curl --socks5-hostname` と `ALL_PROXY=socks5h://` の双方で `"IsTor":true`、
2MB のダウンロードが 184KB/s で完走(= SENDME が両レベルで動作)。

計画から意図的に外した点、および計画になかった追加は次のとおり。

1. **CREATE_FAST を追加した**(計画外・必須)。最初のコンセンサスを取るには
   1 ホップ回路が要るが、その時点ではどのリレーの `KP_onion_ntor` も分からない。
   C Tor も同じ方法で起動する。ディレクトリ取得の 1 ホップ回路に限って使う。
2. **`OPENSSL_free` は使えない**。OpenSSL 3 ではマクロであってエクスポートされた
   シンボルではない。`i2d_X509(x, NULL)` で長さを得てから自前バッファに書く方式にした。
   `SSL_set_tlsext_host_name` も同様にマクロなので SNI は送らない(リレーは要求しない)。
2a. **OpenSSL はリンク時ではなく実行時に `dlopen` で読み込む**(2026-09-02 追加)。
   `#[link(name = "ssl")]` はリンカに `libssl.so` を探させるが、これは `-dev`
   パッケージだけが入れるバージョンなしのシンボリックリンクで、配備先のコンテナには
   `libssl.so.3` しか無く `unable to find library -lssl` で失敗した。§0.3 の前提
   (「`.so.3` があればよい」)を満たすため、全エントリポイントを `dlsym` で解決する
   方式に変更した。バイナリの `DT_NEEDED` から OpenSSL が消える。
   探索順は `TOR_LIBSSL`/`TOR_LIBCRYPTO` → `TOR_OPENSSL_DIR` → soname →
   よくあるライブラリディレクトリ。マクロ 1 つから「関数ポインタの構造体・解決処理・
   同名同シグネチャの呼び出しラッパ」を生成しているので、呼び出し側は無変更。
3. **チャネルの I/O は poll(2) 駆動の単一スレッド**にした。計画の
   「reader スレッド + `Mutex<SslStream>`」だと 1 つの `SSL` オブジェクトを
   読み書き 2 スレッドから同時に触ることになり、OpenSSL はそれを保証しない。
   送信側はキューに積んで UnixStream ペアで I/O スレッドを起こす。
4. **フォールバックは 200 件**を埋め込んだ(`fallback_dirs.inc` の 291 行のうち
   91 行は IPv6 の継続行)。認証局は 9 局(bridge の Serge を除外)。
5. **ストリーム単位の SENDME はアプリがバッファを読み切ってから送る**。
   仕様の「フラッシュ待ちが 10 セル未満」に相当する条件をバッファ占有量で近似し、
   遅い読み手に対して実際にバックプレッシャがかかるようにした。
   回路単位の SENDME は受信時に即返す(C Tor と同じ)。
6. **`bandwidth-weights` は未実装**(計画どおり初版では無視)。`src/tor/path.rs` に
   TODO を残した。ガードは 1 台固定で `state/guard` に永続化。
7. **ディレクトリ取得の経路**: 起動時はフォールバック、以降はガードへの 1 ホップ。
   どのフォールバックも応答しない場合のみ認証局に直接つなぐ。

---

## 6. 仕様の参照先

ローカルに torspec をクローンして grep するのが速い:
`git clone --depth 1 https://gitlab.torproject.org/tpo/core/torspec.git` → `spec/` 以下。

| トピック | ファイル(spec/ 配下) |
|---|---|
| セル形式 | tor-spec/cell-packet-format.md, tor-spec/preliminaries.md |
| リンクハンドシェイク、CERTS、NETINFO | tor-spec/negotiating-channels.md |
| Ed25519 証明書 | cert-spec.md |
| CREATE2 / ntor / EXTEND2 / link specifier | tor-spec/create-created-cells.md |
| 鍵導出 KDF-RFC5869 | tor-spec/setting-circuit-keys.md |
| RELAY セル、ダイジェスト、暗号順序 | tor-spec/relay-cells.md, tor-spec/routing-relay-cells.md |
| RELAY_EARLY | tor-spec/relay-early.md |
| ストリーム開閉、END 理由 | tor-spec/opening-streams.md, tor-spec/closing-streams.md |
| フロー制御、SENDME v1 | tor-spec/flow-control.md |
| DESTROY 理由 | tor-spec/tearing-down-circuits.md |
| コンセンサス形式と署名 | dir-spec/consensus-formats.md, dir-spec/netdoc.md |
| 認証局の鍵証明書 | dir-spec/creating-key-certificates.md |
| microdesc | dir-spec/computing-microdescriptors.md |
| ダウンロード URL | dir-spec/general-use-http-urls.md, dir-spec/directory-cache-operation.md |
| クライアントの取得タイミング | dir-spec/client-operation.md |
| 経路選択(将来) | path-spec/, guard-spec/ |

参考実装(読むと早い): C Tor `src/core/or/`(`onion_ntor.c`, `relay.c`, `sendme.c`,
`channeltls.c`, `torcert.c`)、Python の torpy(純 Python の Tor クライアント)。

---

## 7. 既知のリスクと対処

- **ntor(v1)の廃止**: 現在は全リレーが受け付けるが、将来 ntor-v3 のみになる可能性がある。
  `ntor.rs` はハンドシェイクを trait 化して差し替えられるようにしておく。
- **window 方式フロー制御の廃止**: 輻輳制御(cc)は ntor-v3 拡張で交渉するので、
  ntor(v1)を使う限り window 方式が使われる。上と同じ理由で将来課題。
- **リンク v5 のパディング**: v5 を名乗らなければ PADDING_NEGOTIATE は来ない。
  それでも PADDING(0)/VPADDING(128)は来るので CircID 0 のセルは黙って捨てる。
- **時計ずれ**: コンセンサスの `valid-until` と証明書の期限判定はシステム時計に依存する。
  ずれが大きいと bootstrap できないので、エラーメッセージに現在時刻と valid-after を出す。
- **匿名性**: 経路重み付けとガード運用が簡略なので、本家より推測攻撃に弱い。README に明記する。
- **OpenSSL のバージョン差**: 1.1 系では関数名・マクロが異なる。3.x のみサポートと明記する。
