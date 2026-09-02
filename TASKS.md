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
   (Onion service のクライアント側だけは第 II 部(§8 以降、M9〜M14)で追加する。)
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

---

# 第 II 部 — Onion service(v3)クライアント 実装計画

第 I 部(M0〜M8)の上に、`.onion` v3 アドレスへ接続するクライアント機能を足す。
サービス側(自分が onion service を公開する)は対象外。仕様は
`spec/rend-spec/` を正とし、本書には実装に必要なバイト列・鍵導出の要点と落とし穴だけを書く。

---

## 8. 背景と決定事項

### 8.1 現状の挙動

`.onion` を SOCKS5 で受けると、通常のホスト名として 3 ホップ回路の出口に RELAY_BEGIN を
送っている。出口は `.onion` を DNS 解決できないので END(RESOLVEFAILED)が返り、SOCKS には
`04 host unreachable` が返る。バグではなく未実装。

### 8.2 決定事項

1. **依存ゼロは維持する**。SHA3-256 / SHAKE-256 / AES-256-CTR は OpenSSL 3 に FFI を足す。
   **Ed25519 の点演算(鍵ブラインド)だけは OpenSSL が API を持たないので純 Rust で書く**
   (§9 M9 参照。約 400 行、これが本計画で唯一の「暗号を自前実装する」箇所)。
2. **対象は v3 のみ**(56 文字 + `.onion`)。v2(16 文字)は拒否して SOCKS `04` を返す。
3. **クライアント認証(descriptor cookie / `intro-auth-required`)は非対応**。
   該当サービスには「認証が必要」とログを出して `02 not allowed` を返す。
4. **HSDir リング計算のために HSDir フラグを持つ全リレーの microdesc が必要**
   (`id ed25519` 行が要る。コンセンサスには Ed25519 識別子が無い)。約 4,000〜5,000 件、
   1.5〜2MB を **初回の `.onion` 要求時に遅延取得**し、既存のディスクキャッシュに載せる。
   メモリには `(RSA id 20B, Ed25519 id 32B)` の対だけ持つ(約 250KB)。
5. **1 つの onion アドレスに対して rendezvous 回路は 1 本**を維持し、複数ストリームを載せる
   (C Tor と同じ)。回路の寿命・上限は既存の回路プールに相乗りする。
6. **INTRODUCE1 に輻輳制御拡張は付けない**(第 I 部で cc を使わないのと整合)。
   `legacy-key`(TAP)を要求する intro point は無いものとして無視する。
7. **descriptor は 3 ホップ回路の終端 HSDir から BEGIN_DIR で取る**(rend-spec の要求)。
   intro / rendezvous 回路も 3 ホップ。rendezvous 回路には 4 ホップ目として
   「仮想ホップ」(サービス)が乗る。

### 8.3 用語(この部で使う記号)

- `H(x)` = SHA3-256。`KDF(x, n)` = SHAKE-256 の先頭 n バイト。
- `MAC(key, msg)` = `H(INT_8(len(key)) | key | msg)`。**`INT_8` は 8 バイト big-endian**
  (第 I 部の `INT8` = 1 バイトとは別物。rend-spec の表記に合わせる)。
- `A` = onion サービスの長期 Ed25519 公開鍵(アドレスに埋め込まれている)。
- `A'` = 時刻周期ごとにブラインドした公開鍵。descriptor の署名鍵の親、HSDir の索引鍵。
- `TP` = time period(既定 1440 分、12:00 UTC 切り替え)。`SRV` = shared random value。
- `IP` = introduction point、`RP` = rendezvous point。

---

## 9. アーキテクチャ(追加分)

```
src/
  ffi/
    hash.rs          Digest を SHA-1 固定から md 選択式へ(sha3_256 追加)、shake256(data, n) 追加
    aes.rs           Aes256Ctr 追加(Aes128Ctr と同じ形。可能なら鍵長ジェネリックに統合)
  crypto/
    ed25519_point.rs 純 Rust: fe25519(5×51bit)、点の伸長/圧縮、スカラー倍(ブラインド専用)
    base32.rs        RFC 4648 小文字 base32 の decode(onion アドレス用)
  tor/
    circuit.rs       (改修)制御セルの待ち受け mailbox、send_control、add_virtual_hop、
                     Hop の暗号方式を hop ごとに切替(SHA-1/AES-128 か SHA3-256/AES-256)
    client.rs        (改修)build_circuit_to(last: &RelayInfo)、connect_onion(addr, port)、
                     HSDir 用 Ed25519 id 表の遅延構築
    hs/
      address.rs     .onion のパース・チェックサム検証、credential/subcredential
      blind.rs       時刻周期、ブラインド係数 h、A' の導出
      hsdir.rs       SRV 選択、hs_index / hsdir_index、担当 HSDir 6 台の決定
      descriptor.rs  descriptor の取得、外層署名検証、2 段復号、内層パース(intro point 一覧)
      ntor.rs        hs-ntor(INTRODUCE1 の暗号鍵、RENDEZVOUS2 の検証と回路鍵)
      rendezvous.rs  ESTABLISH_RENDEZVOUS / INTRODUCE1 / RENDEZVOUS2 の流れと再試行
  socks5.rs          (改修)`.onion` を検出して connect_onion に振り分け、失敗理由の写像
```

スレッドモデルは変えない。rendezvous 回路の確立は SOCKS 接続スレッド上で同期的に行う
(intro 回路と RP 回路の構築は逐次でよい。並列化は後回し)。

---

## 10. マイルストーン

各マイルストーンは第 I 部と同じく、完了条件を満たしたらコミットし、§5 のメモリ検証を通す。
`cargo clippy --all-targets -- -D warnings` と `cargo fmt --check` も維持する。

### M9. 暗号プリミティブの追加(`ffi/hash.rs`, `ffi/aes.rs`, `crypto/`)

- [ ] FFI 追加: `EVP_sha3_256`, `EVP_shake256`, `EVP_DigestFinalXOF`, `EVP_aes_256_ctr`。
      `ffi/mod.rs` のマクロに行を足すだけで呼び出しラッパが生える。
- [ ] `hash::sha3_256(data) -> [u8; 32]`(one-shot、`EVP_Digest`)。
- [ ] `hash::shake256(data, out_len) -> Vec<u8>`: `EVP_DigestInit_ex(ctx, EVP_shake256())` →
      `EVP_DigestUpdate` → `EVP_DigestFinalXOF(ctx, out, out_len)`。
      **`EVP_DigestFinalXOF` は 1 コンテキストにつき 1 回しか呼べない**ので、
      出力長を先に決めて一度で取り出す(必要な最大長は 128 バイト)。
- [ ] `Digest` の汎用化: `Digest::sha1()` に加えて `Digest::sha3_256()`。`peek` の戻り値は
      `[u8; 20]` 固定なので、`peek_into(&mut [u8])` か `peek_vec()` に変え、既存の
      `peek_prefix::<N>` はそのまま使えるようにする。`Clone`(`EVP_MD_CTX_copy_ex`)は
      SHA3 でも動く。
- [ ] `Aes256Ctr`: `Aes128Ctr` と同じ実装で `EVP_aes_256_ctr` と鍵 32 バイト。
- [ ] **純 Rust Ed25519 点演算**(`crypto/ed25519_point.rs`)。用途はブラインド `A' = h·A` のみ。
  - 体 `GF(2^255 - 19)`: 5 limb × 51 bit(`u64`、積は `u128`)。add / sub / mul / square /
    `invert`(フェルマー、`pow(p-2)`)/ `pow22523`(平方根用)。
  - 点は extended 座標 `(X, Y, Z, T)`。加算(`-x^2 + y^2 = 1 + d x^2 y^2`、`d = -121665/121666`)、
    倍算、**可変時間の double-and-add でよい**(`h` は公開情報から決まる値で秘密ではない)。
  - 圧縮: `y` の little-endian 32 バイト、最上位ビットに `x` の偶奇。伸長: `x^2 = (y^2-1)/(d y^2+1)`
    を `pow22523` で解き、`x^2` が一致しなければ `sqrt(-1)` を掛け、それでも駄目なら不正な点。
  - 出力は圧縮形式 32 バイト。以降の署名検証は OpenSSL の Ed25519 verify(既存)に渡す。
  - テストベクタ: C Tor の `src/test/ed25519_vectors.inc`
    (https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/test/ed25519_vectors.inc)の
    `ED25519_PUBLIC_KEYS` × `ED25519_BLINDING_PARAMS` → `ED25519_BLINDED_PUBLIC_KEYS`。
    **`ED25519_BLINDING_PARAMS` は clamp 前の値**なので、`param[0] &= 248; param[31] &= 63;
    param[31] |= 64` してから掛ける(C Tor `ed25519_donna_blind_public_key` と同じ)。
    加えて RFC 8032 §7.1 の公開鍵 3 つで「伸長 → 圧縮」が恒等になることを確認する。
- [ ] `crypto/base32.rs`: RFC 4648 アルファベット `a-z2-7`(小文字。大文字も受ける)、
      パディング無し、56 文字 → 35 バイト。
- [ ] 単体テスト: SHA3-256("abc") = `3a985da7…`、SHAKE-256("abc", 32) の既知値
      (`483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739`)、
      AES-256-CTR の NIST SP800-38A F.5.5、上記の ed25519 ブラインドベクタ、base32 の往復。
- 完了条件: `cargo test` が通り、`MemoryMax=200M` でビルドが通る。

### M10. アドレス・時刻周期・HSDir リング(`hs/address.rs`, `hs/blind.rs`, `hs/hsdir.rs`)

- [ ] onion アドレス(rend-spec/encoding-onion-addresses.md):
      `onion_address = base32(PUBKEY(32) | CHECKSUM(2) | VERSION(1)=0x03)`、
      `CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[0..2]`。
      末尾の `.onion` を(大文字小文字を無視して)剥がし、長さ 56 でなければ v2 か不正として拒否。
      チェックサムと VERSION を検証してから `A` を取り出す。
- [ ] credential: `N_hs_cred = H("credential" | A)`、
      `N_hs_subcred = H("subcredential" | N_hs_cred | A')`。`A'` は下で求める。
- [ ] 時刻周期(rend-spec/shared-random-and-time-periods.md 相当):
  - `period_length` = コンセンサス `params` の `hsdir-interval`(分、既定 1440)。
  - `period_num = floor((now_minutes - 12*60) / period_length)`。**`now` はコンセンサスの
    `valid-after` を使う**(C Tor の `hs_get_time_period_num(0)` と同じ。システム時計より HSDir と
    ずれにくい)。
  - テスト: `2016-04-13 11:59:59 UTC` → 16903、`2016-04-13 12:00:00 UTC` → 16904。
- [ ] ブラインド係数(rend-spec/keyblinding.md 相当):
      `h = H(BLIND_STRING | A | s | B | N)` で
      `BLIND_STRING = "Derive temporary signing key" | 0x00`(**NUL 1 バイトを含む**)、
      `s` = 空(クライアント認証なし)、
      `B = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"`
      (**ベースポイントを 10 進の文字列として**そのまま入れる。括弧・カンマ・空白込み)、
      `N = "key-blind" | INT_8(period_num) | INT_8(period_length)`。
      `h` を clamp(`h[0] &= 248; h[31] &= 63; h[31] |= 64`)して `A' = h·A`(M9 の点演算)。
- [ ] コンセンサスのパース追加(`dir/consensus.rs`): `shared-rand-previous-value <reveals> <b64>`、
      `shared-rand-current-value <reveals> <b64>`(各 32 バイト)、`params` から
      `hsdir-interval`、`hsdir_n_replicas`(既定 2)、`hsdir_spread_fetch`(既定 3)。
      `Consensus` 構造体にフィールドを足す。既存の「本文は保持しない」方針は維持。
- [ ] SRV の選択: TP は 12:00 UTC に始まり、SRV は 00:00 UTC に更新される。
      **その TP が始まった時点で current だった SRV** を使う。すなわち `valid-after` の時刻が
      `[12:00, 24:00)` なら `shared-rand-current-value`、`[00:00, 12:00)` なら
      `shared-rand-previous-value`。どちらも無い場合は
      `disaster_srv = H("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))`。
- [ ] HSDir 用 Ed25519 id 表(`client.rs`): `FLAG_HSDIR` を持つ全 `RouterStatus` の microdesc を
      既存 `load_microdescs` 経由で取り、`HashMap<[u8;20], [u8;32]>`(RSA id → Ed25519 id)に
      落として `Mutex<Option<HsdirTable>>` に保持。コンセンサスが更新されたら作り直す。
      **`MAX_CACHED_MICRODESCS = 2000` を超える**ので、この用途では `Microdesc` を残さず
      id だけ抜いてすぐ捨てる(専用の `collect_ed_ids(digests)` を切る)。
      初回は 92 件 × 約 50 リクエストで 30〜60 秒かかる。`TOR_LOG=info` で進捗を出す。
      `id ed25519` の無い microdesc のリレーはリングから除外する。
- [ ] リング計算(rend-spec/hsdir-ring.md 相当):
      `hs_index(replica) = H("store-at-idx" | A' | INT_8(replica) | INT_8(period_length) | INT_8(period_num))`、
      `hsdir_index(node) = H("node-idx" | node_ed25519_id | SRV | INT_8(period_num) | INT_8(period_length))`。
      **2 つで `period_length` と `period_num` の順序が逆**。仕様どおりであってタイプミスではない。
      `replica` は **1 から** `hsdir_n_replicas` まで。全 HSDir を `hsdir_index` で昇順に並べ、
      各 replica について `hsdir_index >= hs_index(replica)` となる最初のノードから
      `hsdir_spread_fetch` 台を(末尾で先頭に巻き戻して)取り、重複を除く。通常 6 台。
- [ ] 単体テスト: アドレスの往復とチェックサム不正の検出、時刻周期、SRV 選択の境界
      (11:59 / 12:00)、リングの巻き戻しと重複除去(ダミーの id で)。
- 完了条件: `cargo test -- --ignored` のテストで実ネットワークのコンセンサスから、
      既知の onion(下記 §12)に対する担当 HSDir 6 台の識別子と `A'` をログ出力できる。

### M11. 終端指定の 3 ホップ回路と descriptor の取得・復号(`client.rs`, `hs/descriptor.rs`)

- [ ] `TorClient::build_circuit_to(last: &RelayInfo) -> io::Result<Circuit>`: guard(固定)→
      middle(既存の選び方、`last` と同一 /16・family を避ける)→ `last` へ EXTEND2。
      既存の `build_circuit(port)` はこれを使って exit を選ぶ形に寄せる(exit 選択だけが差)。
      HSDir / IP / RP の 3 用途で共有する。
- [ ] 取得: `RelayInfo` を `RouterStatus` + microdesc から作り(既存 `relay_info`)、
      `build_circuit_to` → `begin_dir_stream` → 既存 `fetch::get(circuit, "/tor/hs/3/<A' の base64(パディング無し、43 文字)>")`。
      404 は「その HSDir に無い」なので次の HSDir へ。6 台をランダム順に最大 3 台まで試す。
- [ ] 外層のパース(rend-spec/hs-desc-encoding.md 相当):
      `hs-descriptor 3`、`descriptor-lifetime <分>`、`descriptor-signing-key-cert`(ED25519 CERT
      オブジェクト、既存 `certs.rs` でパース)、`revision-counter <n>`、`superencrypted`
      (MESSAGE オブジェクト)、`signature <b64>`。
  - 証明書: CertType **0x08**、拡張 type 4 の鍵が `A'` と一致、`A'` で署名検証、期限内。
    証明された鍵 = descriptor 署名鍵 `KP_hs_desc_sign`。
  - 署名: 署名対象は `"Tor onion service descriptor sig v3"` | 文書先頭から `signature `
    (末尾のスペースを含む)まで。`KP_hs_desc_sign` で検証。
  - `descriptor-lifetime` と証明書期限を過ぎたものは捨てる。
- [ ] 2 段復号(`superencrypted` → 中層 → `encrypted` → 内層)。両段とも同じ構造:
  - blob = `SALT(16) | ENCRYPTED | MAC(32)`。
  - `secret_input = SECRET_DATA | N_hs_subcred | INT_8(revision_counter)`、
    `keys = KDF(secret_input | SALT | STRING_CONSTANT, 32+16+32)` →
    `SECRET_KEY(32) | SECRET_IV(16) | MAC_KEY(32)`。
  - `MAC = H(INT_8(32) | MAC_KEY | INT_8(16) | SALT | ENCRYPTED)` を定数時間比較してから
    `AES-256-CTR(SECRET_KEY, IV=SECRET_IV)` で復号。
  - 外段: `SECRET_DATA = A'`、`STRING_CONSTANT = "hsdir-superencrypted-data"`。
    内段: `SECRET_DATA = A'`(クライアント認証なし)、`STRING_CONSTANT = "hsdir-encrypted-data"`。
  - 復号結果の末尾は NUL でパディングされている(10KB 単位)。**末尾の NUL を剥がしてから**
    テキストとして扱う。
- [ ] 中層は読み飛ばしてよい(`desc-auth-type x25519`、`desc-auth-ephemeral-key`、`auth-client` × N
      はクライアント認証なしでもダミーが入っている)。`encrypted` の MESSAGE を取って内段へ。
- [ ] 内層のパース: `create2-formats 2`(2 を含まなければ拒否)、`intro-auth-required`(あれば
      非対応として拒否)、`single-onion-service`(無視)、`flow-control`(無視)。
      以下を `introduction-point` ごとに 1 組:
  - `introduction-point <b64>`: 中身は EXTEND2 と同じ `NSPEC | {LSTYPE LSLEN LSPEC}*`。
    [00] IPv4、[02] legacy id、[03] Ed25519 id を拾い、[01] IPv6 は無視。
  - `onion-key ntor <b64>`: IP の `KP_onion_ntor`(EXTEND2 に使う)。
  - `auth-key`(ED25519 CERT、CertType **0x09**、`KP_hs_desc_sign` で署名、期限内):
    証明された鍵 = `AUTH_KEY`(INTRODUCE1 で名指しする鍵)。
  - `enc-key ntor <b64>`: IP の x25519 鍵 `B`(hs-ntor の相手鍵)。
  - `enc-key-cert`(CertType **0x0B**): 署名の検証だけ行う。証明された鍵は `B` を Ed25519 に
    変換した cross-cert で、変換の検証は任意(descriptor 全体が署名済みなので省いても安全性は
    落ちない。TODO コメントを残す)。
  - `legacy-key` / `legacy-key-cert` は読み飛ばす。
  - 上の 4 要素から `IntroPoint { relay: RelayInfo, auth_key: [u8;32], enc_key: [u8;32] }` を作る。
- [ ] descriptor キャッシュ: `HashMap<onion_address, (Descriptor, fetched_at, period_num)>`。
      `descriptor-lifetime`(既定 180 分)か TP の切り替えで失効。ディスクには置かない。
- [ ] 単体テスト: 復号は「自分で暗号化した blob を復号する」往復テストで十分
      (鍵導出と MAC の式が仕様と一致していることは M11 の完了条件で実機確認する)。
      内層パースは固定の文字列で。
- 完了条件: `cargo test -- --ignored` で既知の onion(§12)の descriptor を取得・復号し、
      intro point の台数と `AUTH_KEY` をログ出力できる。

### M12. 回路の一般化と hs-ntor(`circuit.rs`, `hs/ntor.rs`)

- [ ] `Hop` の暗号方式を hop ごとに選べるようにする: `enum HopCipher { Aes128(Aes128Ctr), Aes256(Aes256Ctr) }`
      と `Digest`(md 選択済み)。既存 3 ホップは SHA-1/AES-128、仮想ホップは
      **SHA3-256 / AES-256-CTR**。`build_relay_cell` / `decrypt_inbound` は `peek_prefix::<4>` を
      使っているのでそのまま動く。**SENDME v1 が引用する digest は SHA3 でも先頭 20 バイト**
      (`last_recv_digest: [u8; 20]` は変えなくてよい)。
- [ ] `Circuit::add_virtual_hop(keys: HsCircuitKeys)`: `hops` に SHA3/AES-256 の Hop を push する。
      以降 `open_stream` は最後の hop(= サービス)を宛先にするので変更不要。
- [ ] 制御セルの mailbox: `State.handshake: Option<Result<Vec<u8>,String>>` を
      `control: VecDeque<(u8 /*relay cmd*/, Vec<u8>)>` に一般化し、
      `RELAY_EXTENDED2` と同様に **`RENDEZVOUS_ESTABLISHED(39)`、`INTRODUCE_ACK(40)`、
      `RENDEZVOUS2(37)`** を `handle_relay` で積んで `event.notify_all()`。
      `wait_for_control(cmd, timeout) -> io::Result<Vec<u8>>` を `wait_for_handshake` と同じ形で書く。
- [ ] `Circuit::send_control(relay_cmd, payload)`: StreamID 0、最後の hop 宛て、RELAY_EARLY なし。
- [ ] 定数追加: `RELAY_ESTABLISH_RENDEZVOUS = 33`、`RELAY_INTRODUCE1 = 34`、`RELAY_RENDEZVOUS2 = 37`、
      `RELAY_RENDEZVOUS_ESTABLISHED = 39`、`RELAY_INTRODUCE_ACK = 40`。
- [ ] `begin_stream` の onion 版: payload は **`":<port>\0"`(ホスト名は空)**。C Tor は
      rendezvous 回路では address を送らない。`begin_stream_onion(port)` を足す。
- [ ] hs-ntor(rend-spec/introduction-protocol.md「ntor-with-extra-data」):
  - `PROTOID = "tor-hs-ntor-curve25519-sha3-256-1"`、`t_hsenc = PROTOID | ":hs_key_extract"`、
    `t_hsverify = PROTOID | ":hs_verify"`、`t_hsmac = PROTOID | ":hs_mac"`、
    `m_hsexpand = PROTOID | ":hs_key_expand"`。
  - クライアントの一時鍵 `x, X`(既存 `x25519::EphemeralSecret`)。`B` = IP の `enc-key`。
  - INTRODUCE1 用: `intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID`、
    `info = m_hsexpand | N_hs_subcred`、
    `hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, 64)` → `ENC_KEY(32) | MAC_KEY(32)`。
  - RENDEZVOUS2 用: 受信 `Y(32) | AUTH(32)` に対し
    `rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID`、
    `NTOR_KEY_SEED = MAC(rend_secret_hs_input, t_hsenc)`、
    `verify = MAC(rend_secret_hs_input, t_hsverify)`、
    `auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"`、
    `AUTH == MAC(auth_input, t_hsmac)` を定数時間比較。
    `K = KDF(NTOR_KEY_SEED | m_hsexpand, 128)` → `Df(32) | Db(32) | Kf(32) | Kb(32)`。
    **`MAC(key, msg)` の第 1 引数が key**(`H(INT_8(len) | key | msg)`)。C Tor の
    `crypto_mac_sha3_256(out, key, msg)` の引数順と同じ。
  - `NtorClient` と同様に `HsNtorClient::new(auth_key, enc_key)` / `introduce1_keys()` /
    `finish(reply) -> HsCircuitKeys` の形にする。第 I 部 §7 の「ハンドシェイクは差し替え可能に」
    という方針に合わせ、`CircuitKeys` とは別型にする(鍵長が違う)。
- [ ] 単体テスト: 仮想ホップ付き 4 ホップの `state_with_hops` で既存の「onion 層が目的の hop で
      剥がれる」テストを SHA3/AES-256 の hop に対しても回す。hs-ntor は C Tor
      `src/test/test_hs_ntor.c` の往復(サーバ側も同じ式で書けるので、テスト内にサーバ側を実装して
      往復させる)。
- 完了条件: `cargo test` が通り、既存の実機テスト 4 件が退行していない。

### M13. Rendezvous と Introduce(`hs/rendezvous.rs`, `client.rs`)

- [ ] RP の選択: `Running, Valid, Stable, Fast` を持つリレーから帯域重みで 1 台
      (guard と同一 /16・family を避ける。exit フラグは不要)。microdesc を取って `RelayInfo` にする。
- [ ] 手順(rend-spec/rendezvous-protocol.md, introduction-protocol.md):
  1. `build_circuit_to(RP)`。`cookie = RAND(20)`。`send_control(ESTABLISH_RENDEZVOUS, cookie)`。
     `wait_for_control(RENDEZVOUS_ESTABLISHED, 30s)`(本体は空)。
  2. descriptor の intro point をランダム順に 1 つ選び `build_circuit_to(IP.relay)`。
  3. INTRODUCE1 を組む(**1 セルに収める。498 バイト以内**):
     ```
     LEGACY_KEY_ID(20) = 全 0
     AUTH_KEY_TYPE(1)  = 0x02 (ed25519)
     AUTH_KEY_LEN(2)   = 32
     AUTH_KEY(32)
     N_EXTENSIONS(1)   = 0
     ENCRYPTED         = CLIENT_PK X(32) | ENCRYPTED_DATA | MAC(32)
     ```
     `ENCRYPTED_DATA` の平文:
     ```
     RENDEZVOUS_COOKIE(20)
     N_EXTENSIONS(1)   = 0
     ONION_KEY_TYPE(1) = 0x01 (ntor)
     ONION_KEY_LEN(2)  = 32
     ONION_KEY(32)     = RP の KP_onion_ntor
     NSPEC(1) | link specifiers(RP: [00] IPv4, [02] legacy id, [03] Ed25519 id)
     PAD               = セルの残りを 0 で埋める
     ```
     `AES-256-CTR(ENC_KEY, IV=0)` で暗号化し、`MAC = MAC(MAC_KEY, LEGACY_KEY_ID から ENCRYPTED_DATA の末尾まで)`
     (**MAC より前のセル全体**が対象。`CLIENT_PK` も含む)。
  4. `send_control(INTRODUCE1, cell)` を IP 回路へ。`wait_for_control(INTRODUCE_ACK, 30s)`:
     `STATUS(2)` が 0 なら成功。1 = 鍵が未知(descriptor が古い → 再取得)、2 = 形式不正。
     ACK を受けたら IP 回路は閉じてよい。
  5. RP 回路で `wait_for_control(RENDEZVOUS2, 60s)` → `HANDSHAKE_INFO = Y(32) | AUTH(32)`。
     `HsNtorClient::finish` で鍵を得て `add_virtual_hop`。
  6. `begin_stream_onion(port)` で CONNECTED まで待つ。以降は通常の `TorStream`。
- [ ] 再試行: intro point は最大 3 つ試す。INTRODUCE_ACK が 1(未知の鍵)なら descriptor
      キャッシュを捨てて 1 回だけ取り直す。RP 回路の失敗は RP を選び直す。
      全体の上限は 90 秒(既存の回路作成 60 秒とは別枠)。
- [ ] `TorClient::connect_onion(address: &OnionAddress, port) -> io::Result<TorStream>`:
      `Mutex<HashMap<onion_address, Circuit>>` で rendezvous 回路を再利用し、閉じていたら作り直す。
      `MAX_CIRCUITS` の数え上げに含める。`MAX_CIRCUIT_AGE` も同じ値でよい。
- [ ] 失敗の分類(SOCKS 写像用): descriptor が 6 台とも無い → `NotFound`、
      `intro-auth-required` → `PermissionDenied`、intro/rendezvous のタイムアウト → `TimedOut`、
      その他 → `Other`。既存 `reply_code` の `io::ErrorKind` 分岐に乗る。
- 完了条件: `cargo test -- --ignored` で既知の onion(§12)に HTTP GET し、200 が返る。

### M14. SOCKS5 統合と仕上げ(`socks5.rs`, `main.rs`, README)

- [ ] `socks5.rs`: `ATYP_DOMAIN` で受けたホスト名が(大文字小文字を無視して)`.onion` で終わるなら
      `OnionAddress::parse` に通し、成功なら `connect_onion`、v2 や不正なら `04 host unreachable`
      を返してログに理由を出す。それ以外は従来どおり `connect`。
      `ATYP_IPV4` に `.onion` は来ないので考慮不要。
- [ ] ログ: descriptor 取得先 HSDir、選んだ IP と RP、各段の所要時間を `TOR_LOG=debug` で出す。
      **onion アドレスそのものは `info` では出さない**(ログから訪問先が分かる)。`debug` のみ。
- [ ] 計測を README に追記: 初回の HSDir 表構築の所要時間、`.onion` 初回接続の所要時間、
      2 回目(回路再利用)の所要時間、接続後の `VmHWM`(目標: 従来 + 数 MB 以内)。
- [ ] README の Limitations を更新: 「onion services」を「Not implemented」から外し、
      「クライアント認証と v2 は非対応、サービス側は非対応」に書き換える。
      `TASKS.md` の §0.2 の記述も同期する。
- [ ] `cargo clippy --all-targets -- -D warnings`、`cargo fmt`、§5 のメモリ検証。
- 完了条件: `curl --socks5-hostname 127.0.0.1:$SERVER_PORT http://<§12 の onion>/` が本文を返す。
      同時に `https://check.torproject.org/api/ip` が従来どおり `"IsTor":true`。

---

## 11. FFI 関数一覧(追加分)

`libcrypto`: `EVP_sha3_256`, `EVP_shake256`, `EVP_DigestFinalXOF`, `EVP_aes_256_ctr`

いずれも OpenSSL 1.1.1 以降に実体があり、3.x ではエクスポートされた関数(マクロではない)。
`EVP_MD_CTX_copy_ex` は SHA3 / SHAKE のコンテキストにも使える。

---

## 12. 検証用の onion アドレス

実機テスト(`#[ignore]`)と完了条件には、運用が安定している公開サービスを使う。
死んでいたら差し替える(`curl --socks5-hostname` を本家 tor で試して生存確認してから使う):

- torproject.org: `2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion`(HTTP、80)
- DuckDuckGo: `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`(HTTP/HTTPS)

比較用に本家 tor を立てて同じ `.onion` に到達できることを先に確かめておくと、
失敗したとき「自分の実装」と「相手の停止」を切り分けられる。

---

## 13. 仕様の参照先(追加分)

| トピック | ファイル(spec/ 配下) |
|---|---|
| 全体像、用語、鍵の一覧 | rend-spec/overview.md, rend-spec/protocol-overview.md |
| アドレスとチェックサム | rend-spec/encoding-onion-addresses.md |
| 鍵ブラインド、credential | rend-spec/keyblinding.md(付録 A 相当) |
| 時刻周期、SRV、HSDir リング | rend-spec/shared-random-and-time-periods.md, rend-spec/hsdir-ring.md |
| descriptor の形式・暗号化・証明書 | rend-spec/hs-desc-encoding.md, rend-spec/hsdesc-outer.md, rend-spec/hsdesc-encrypt.md |
| descriptor の取得 URL とクライアント動作 | rend-spec/hsdir.md, dir-spec/general-use-http-urls.md |
| INTRODUCE1 / INTRODUCE_ACK、hs-ntor | rend-spec/introduction-protocol.md |
| ESTABLISH_RENDEZVOUS / RENDEZVOUS2、仮想ホップの鍵 | rend-spec/rendezvous-protocol.md |
| 証明書の種別(0x08 / 0x09 / 0x0B) | cert-spec.md |
| SRV 生成側(読むだけ) | srv-spec/ |

torspec のファイル名は改組で変わることがある。`grep -rl "store-at-idx" spec/` のように
本文の定数文字列で探すのが確実。

参考実装: C Tor `src/feature/hs/`(`hs_common.c` のリング計算と時刻周期、`hs_descriptor.c` の
復号、`hs_cell.c` の INTRODUCE1 組み立て、`hs_ntor.c`、`hs_client.c` の再試行)、
`src/lib/crypt_ops/crypto_ed25519.c` の `ed25519_public_blind`。
Rust では arti の `tor-hscrypto`(ブラインドと時刻周期)、`tor-hsclient`(状態遷移)。

---

## 14. 既知のリスクと対処(追加分)

- **Ed25519 点演算の自前実装**: バグがあると `A'` が違う HSDir を指すだけで、暗号的な
  安全性の問題にはならない(秘密を扱わない)。C Tor のテストベクタで固定し、さらに
  実機で descriptor が取れることを完了条件にして二重に確認する。
- **HSDir 表の初回構築が遅い**: 30〜60 秒。ディスクキャッシュにより 2 回目以降は数秒。
  必要なら bootstrap 直後にバックグラウンドで先読みする(初版では遅延取得のまま)。
- **時計ずれ**: TP と SRV の選択を `valid-after` 基準にしているので、システム時計が多少ずれても
  HSDir 側と一致する。ただし descriptor の証明書期限判定は依然システム時計。
- **TP 境界(12:00 UTC)の前後**: サービスは新旧両方の TP に descriptor を置くが、クライアントは
  現在の TP のみで探す(C Tor と同じ)。境界直後に取れない場合があるので、6 台のうち 3 台で
  404 なら残りも試す。
- **INTRODUCE1 が 1 セルに収まらない**: RP の link specifier が IPv4 + legacy + Ed25519 なら
  約 200 バイトで余裕がある。IPv6 を入れない理由の一つ。
- **仮想ホップの digest 種別**: SHA-1 と SHA3-256 で `Digest` の出力長が違う。`peek_prefix::<4>`
  と SENDME の 20 バイトは両方で成立するが、`[u8; 20]` を返す `peek()` を SHA3 の hop で
  呼ばないよう型で分ける。
- **`intro-auth-required` / クライアント認証**: 対応しない。要求された場合は SOCKS `02` を返し、
  ログに「client authorization required」と出す。
