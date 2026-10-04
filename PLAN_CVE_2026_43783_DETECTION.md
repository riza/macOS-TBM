# CVE-2026-43783 Sınıfı XPC Yetkilendirme Hatalarını Yakalama Planı

## Amaç

macOS-TBM'nin, `DesktopServicesHelper` vakasındaki gibi aşağıdaki zinciri statik
olarak yüksek öncelikli ve açıklanabilir bir araştırma adayı olarak çıkarmasını
sağlamak:

```text
XPC komutu ve istemci girdisi
  -> komuta bağlı handler
  -> çağıran profiline bağlı yetkilendirme yolu
  -> istemci kontrollü dosya yolu
  -> path ile açılan descriptor
  -> ayrıcalıklı fchown/fchmod benzeri sink
```

Araç yalnızca elde ettiği ilişkiyi raporlayacak. Bağlantı veya API varlığından
bir yetkilendirme atlatması ya da exploit sonucu çıkarmayacak. Mevcut olgunluk
zinciri korunacak:

```text
SINK_CANDIDATE -> REACHABLE_SINK -> CONTROLLED_SINK -> PRIMITIVE -> IMPACT
```

## Başlangıç durumu

Mevcut rapor `com.apple.DesktopServicesHelper` için doğru kaba sinyalleri zaten
üretiyor:

- root/system servis;
- Mach/XPC giriş noktası;
- hassas entitlement'lar;
- filesystem mutation API'leri;
- `CHOWN_SINK_CANDIDATE`;
- yüksek araştırma önceliği.

Eksik kalan ilişki, belirli bir `request` değerini belirli handler ve sink ile
bağlamak. Mevcut raporda chown yolu `UNKNOWN_NO_CALL_PATH` ve
`UNKNOWN_WRAPPER` ile kalıyor. Ayrıca binary genelindeki doğrulama sinyalleri
`STRONG` görünse bile bu sinyallerin `RepairPermissionsForCloudItems`
operasyonunu koruduğu kanıtlanmıyor.

Çalışma ağacında bu alanlara dokunan yarım prototipler bulunuyor. Uygulamaya
başlarken bunlar ayrı ayrı incelenecek; test edilmemiş prototip davranışı nihai
tasarım kabul edilmeyecek ve kullanıcının diğer değişiklikleri korunacak.

## Kapsam

### Dahil

1. XPC dictionary anahtar ve komut değerlerinin kullanım bağlamıyla çıkarılması.
2. Komut adı, dispatcher ve handler ilişkilerinin statik modellenmesi.
3. Çağıran profillerinin ayrı erişim durumları olarak değerlendirilmesi.
4. Yetkilendirme kontrolünün belirli operasyonu gerçekten koruyup korumadığının
   kontrol akışı üzerinden, başarısız durumda kapalı kalacak biçimde kanıtlanması.
5. İstemci kontrollü path'in `open/openat` sonucundaki descriptor üzerinden
   `fchown/fchmod/ftruncate` gibi sink'lere taşınması.
6. Kaynak doğrulaması ile kaynak üzerinde işlem yetkisinin ayrı raporlanması.
7. JSON, metin, HTML ve TUI çıktılarında yeni kanıtların görünmesi.
8. Sentetik assembly fixture'ları ve savunmasız/düzeltilmiş davranış testleri.

### Kapsam dışı

- XPC mesajı gönderme, fuzzing veya exploit/PoC üretme.
- launchd işlerini yükleme, boşaltma veya değiştirme.
- Bir sink ve eksik statik kontrol gözleminden otomatik CVE hükmü çıkarma.
- `PRIMITIVE` veya `IMPACT` seviyesine yalnızca sezgisel kanıtla yükseltme.
- CVE'ye veya `DesktopServicesHelper` adına sabitlenmiş özel tespit kuralı.

## Kanıt modeli

Her operasyon aşağıdaki soruları ayrı alanlarda cevaplamalı:

| Soru | Önerilen alan | Örnek durumlar |
|---|---|---|
| Çağıran kim? | `caller_profile` | `SANDBOXED`, `UNSANDBOXED`, `ENTITLED`, `UNKNOWN` |
| Servise statik olarak ulaşabilir mi? | `entry_reachability` | `DECLARED`, `CONDITIONAL`, `UNKNOWN` |
| Hangi komut seçildi? | `ipc_operation` | anahtar, değer, dispatcher ve handler kanıtı |
| Kimlik kontrolü var mı? | `identity_verification` | binary-wide, handler-reachable, guards-operation |
| Operasyon izni var mı? | `operation_authorization` | aynı üç kapsam seviyesi |
| Hedef kaynak doğrulanıyor mu? | `resource_validation` | prefix/root check, descriptor binding, metadata-only |
| Çağıranın hedefte yetkisi var mı? | `resource_authorization` | `PROVEN`, `CONDITIONAL`, `UNKNOWN` |
| Girdi sink'e ulaşıyor mu? | `dataflow` | path, descriptor provenance ve kontrollü argümanlar |
| Sonuç kanıtlandı mı? | `post_condition` | ayrı ve varsayılan olarak `UNPROVEN` |

`sandbox_check*` kendi başına güçlü bir yetkilendirme kontrolü sayılmayacak. Bu
API çağıranın sandbox durumunu sınıflandırabilir; güvenlik anlamı, dönen değerin
hangi dala ve hangi operasyon allowlist'ine bağlandığı çözüldüğünde verilecek.

## Uygulama aşamaları

### Aşama 0 — Prototip denetimi ve test tabanı

1. İlgili dosyalardaki mevcut kullanıcı değişiklikleri ile yarım prototipleri
   satır bazında ayır.
2. Değişiklik öncesi test tabanını kaydet:

   ```bash
   python3 -m unittest discover -s tests -t tests -v
   ```

3. Mevcut `results/report.json` içindeki `DesktopServicesHelper` kaydını yalnızca
   karşılaştırma girdisi olarak sakla; farklı macOS sürümü olabileceğini açıkça
   belirt.
4. Prototip kodu ancak odaklı testi varsa tut. Belirsiz parçaları yeniden tasarla.

Çıkış ölçütü: başlangıç test sonucu ve değiştirilecek dosyaların net envanteri.

### Aşama 1 — XPC anahtarları ve operasyon yüzeyi

`collectors/macho.py` içindeki genel “interesting string” filtresine yalnızca
`RepairPermissionsForCloudItems` eklemek yerine, XPC API çağrılarının sabit
argümanlarını bağlama göre çıkar.

Toplanacak örnekler:

- `xpc_dictionary_get_string(message, "request")`;
- `xpc_dictionary_get_data(message, "Paths")`;
- request değeri olarak karşılaştırılan string'ler;
- lookup table içine yerleştirilen komut/handler çiftleri;
- Mach service adı.

Önerilen çıktı:

```json
{
  "request_key": "request",
  "operation": "RepairPermissionsForCloudItems",
  "handler": "sub_10002D744",
  "input_keys": ["Paths"],
  "dispatcher": "sub_10003AB2C",
  "relationship": "PROVEN|INFERRED|UNRESOLVED",
  "evidence": [{"address": "...", "kind": "string-xref|table-entry|call"}]
}
```

İlk uygulama doğrudan sabit argümanları ve basit karşılaştırma zincirlerini
destekleyecek. Function-pointer tabloları çözülemezse operasyon adı korunacak ve
`UNKNOWN_INDIRECT_HANDLER` üretilecek.

Dokunulacak alanlar:

- `collectors/macho.py`: bağlama bağlı IPC string toplama;
- `collectors/dataflow.py`: sabit string/anahtar propagation;
- yeni küçük bir `collectors/xpc_dispatch.py`: operation/handler çıkarımı;
- `models/executable.py`: `ipc_operations` alanı;
- `scanner.py`: collector sonucunu modele aktarma.

Çıkış ölçütü: fixture üzerinde `request`, `RepairPermissionsForCloudItems`,
`Paths` ve handler ilişkisi raporda görünür; çözülemeyen pointer ilişkisinde kesin
handler iddiası oluşmaz.

### Aşama 2 — Çağıran profiline göre erişim ve politika dalları

Tek bir servis erişim listesi yerine operasyon bazında çağıran profilleri üret:

```text
SANDBOXED + mach-lookup izinli
SANDBOXED + mach-lookup bilinmiyor
UNSANDBOXED
PRIVATE_ENTITLEMENT taşıyan istemci
UNKNOWN
```

Mach lookup entitlement'ı istemci tarafı kanıtıdır; sunucunun entitlement kontrolü
ile karıştırılmayacak. Statik olarak yalnızca client binary veya launch metadata
üzerinden görülen entitlement, “declared client capability” olarak raporlanacak;
başarılı bağlantı kanıtı sayılmayacak.

Dispatcher içindeki allowlist şu ilişki olarak modellenmeli:

```text
caller predicate -> allowed operation set -> reject/continue successor
```

`sandbox_check_by_audit_token` sonucu sandboxed çağıranı bir operasyona izin veren
daldan geçiriyorsa bu bir “profil bazlı allowlist” bulgusudur. Otomatik olarak
`AUTHORIZATION_GUARDS_SINK` veya “güvenli” sonucu üretmez.

Dokunulacak alanlar:

- `analyzers/capabilities.py`: profil bazlı reachability ve authorization;
- `models/capability.py`: `caller_profiles`, `policy_paths`;
- `graph/model.py`: kanıt varsa client profile/operation kenarları;
- `rules/capabilities.json`: predicate ve başarı semantiği kuralları.

Çıkış ölçütü: aynı operasyon sandboxed ve unsandboxed profiller için farklı
authorization sonucu taşıyabilir; bilinmeyen Mach lookup izni `UNKNOWN` kalır.

### Aşama 3 — Operation guard için kontrol akışı kanıtı

Mevcut “kontrol çağrısından sonra forward branch var” yaklaşımı yerine sınırlı
bir control-flow graph kullan.

Bir kontrol yalnızca şu şartlarda `*_GUARDS_SINK` olabilir:

1. Kontrol çağrısı handler girişinden sink'e giden bütün desteklenen yolları
   domine eder.
2. Branch gerçekten kontrolün dönüş değerini kullanır.
3. API'nin başarı semantiği deklaratif kuralda bilinir.
4. Başarısız successor sink'e ulaşamaz.
5. Başarılı successor sink'e ulaşır.
6. Çözülemeyen indirect jump, exception edge veya analiz bütçesi varsa sonuç
   `UNKNOWN_CONTROL_FLOW` olur.

Önemli negatif örnek: başarılı kontrol dalı sink'i atlıyor, başarısız dal sink'e
gidiyorsa kontrol kesinlikle guard sayılmamalı.

Önerilen yardımcı modül: `collectors/control_flow.py`. CFG küçük ve bounded
kalmalı; tam decompiler davranışı hedeflenmemeli.

Deklaratif kurallar:

```json
{
  "guard_success_semantics": {
    "AuthorizationCopyRights": "zero",
    "SecCodeCheckValidity": "zero",
    "SecTaskCopyValueForEntitlement": "object_then_boolean"
  }
}
```

`sandbox_check*` için tek bir genel “success” anlamı tanımlanmayacak; operation
policy analizinde predicate olarak ele alınacak.

Çıkış ölçütü: pozitif dominance testi guard üretir; ters dal, bypass yolu ve
indirect jump testleri guard üretmez ve uygun `UNKNOWN_*` nedeni döndürür.

### Aşama 4 — Path → descriptor provenance

`open/openat` bir ara kaynak düğümü üretsin:

```text
RESOURCE_DESCRIPTOR {
  producer: open,
  producer_address,
  path_origin,
  flags_origin,
  returned_register,
  aliases
}
```

Bu düğüm register, stack slot, doğrudan helper argümanı ve basit wrapper return
üzerinden taşınacak. `fchown`, `fchmod`, `ftruncate`, `fstat` gibi descriptor
consumer'larında provenance raporlanacak.

Önemli semantik ayrım:

- `file_descriptor=HIGH`: istemci girdisinden türeyen descriptor seçimi;
- `resource_path=HIGH`: descriptor'ın istemci kontrollü path ile açıldığı kanıtı;
- `descriptor_bound=true`: sink aynı açılmış objeyi kullanıyor;
- `resource_authorization=UNKNOWN`: hedefin izin verilen kaynak kümesinde olduğu
  halen kanıtlanmadı.

Descriptor kullanımı pathname TOCTOU riskini azaltabilir, fakat çağıranın o
kaynak üzerinde işlem yapma yetkisini kanıtlamaz.

Dokunulacak alanlar:

- `rules/capabilities.json`: descriptor producer/consumer semantiği;
- `collectors/dataflow.py`: resource provenance ve alias takibi;
- `analyzers/capabilities.py`: kontrollü kaynak alanları;
- `analyzers/lpe.py`: path authorization ile descriptor integrity ayrımı;
- `models/lpe.py`: `descriptor_provenance`, `resource_authorization`.

Çıkış ölçütü: `xpc input -> open(path) -> fchown(fd, uid, gid)` fixture'ı
`CONTROLLED_SINK` üretir; `ARBITRARY_CHOWN` üretmez. Primitive için ayrıca
operation authorization bypass ve hedef yetkisi kanıtı gerekir.

### Aşama 5 — Kaynak doğrulaması ve hedef kapsamı

İzin verilen kök/prefix kontrollerini descriptor güvenliği ve metadata
kontrollerinden ayır:

- `PATH_SCOPE_GUARD`: hedef izin verilen kökün altında mı;
- `DESCRIPTOR_BINDING`: kontrol edilen ve değiştirilen nesne aynı mı;
- `METADATA_CHECK`: `lstat/fstat`, owner, type veya link count kontrolü;
- `RESOURCE_AUTHORIZATION`: çağıran bu hedefte bu operasyonu yapabilir mi.

`lstat`, `fstat`, hardlink sayısı veya owner karşılaştırması tek başına path scope
guard sayılmayacak. Prefix kontrolünün canonicalization/symlink davranışı
çözülemiyorsa `CONDITIONAL` veya `UNKNOWN` kalacak.

Çıkış ölçütü: iCloud/home benzeri izin verilen kök kontrolü olmayan kontrollü
chown için açık bir “resource authorization unresolved” araştırma sorusu üretilir.

### Aşama 6 — Raporlama ve sıralama

JSON ve insan çıktısına şu bölümleri ekle:

- XPC operation: request key, value, handler ve ilişki seviyesi;
- caller profiles ve her profil için reachability;
- identity verification, operation authorization ve resource authorization;
- path/descriptor provenance;
- guard CFG kanıtı veya `UNKNOWN_*` nedeni;
- next research steps.

Sıralama, aşağıdaki kombinasyona araştırma önceliği vermeli:

```text
privileged service
+ externally selectable operation
+ caller-influenced path/resource
+ ownership/permission/write sink
+ operation/resource authorization unresolved
```

Bu kombinasyon exploitability kanıt puanını yapay biçimde yükseltmemeli.
`NONE_OBSERVED`, bypass kanıtı olarak kullanılmayacak.

Dokunulacak alanlar:

- `reporting/json_report.py`;
- `reporting/html_report.py`;
- `reporting/export.py`;
- `ui.py`;
- gerekiyorsa `rules/scoring.json` ve `rules/lpe.json`.

Çıkış ölçütü: aynı veri JSON, `scan.txt`, HTML ve TUI dossier'ında anlam kaybı
olmadan görünür.

## Test planı

### Collector ve dataflow testleri

1. XPC key sabiti doğru source adına bağlanır.
2. Request karşılaştırma zinciri operation adını çıkarır.
3. Basit function-pointer table operation/handler ilişkisini çıkarır.
4. Çözülemeyen indirect dispatcher `UNKNOWN_INDIRECT_HANDLER` verir.
5. `open(path)` dönüşü `fchown(fd, ...)` sink'ine provenance taşır.
6. Descriptor stack slot ve bir helper üzerinden taşınır.
7. Başka bir descriptor ile overwrite edilen register eski provenance'ı taşımaz.
8. `xpc_dictionary_get_audit_token` saldırgan kontrollü payload source sayılmaz.

### Control-flow testleri

1. Başarısız dal sink'i atlıyorsa guard kanıtlanır.
2. Başarılı dal sink'i atlıyorsa guard kanıtlanmaz.
3. Kontrolden önce sink'e ulaşan alternatif yol dominance'ı bozar.
4. Kontrol sonucu yerine başka register branch'te kullanılıyorsa guard oluşmaz.
5. Bilinmeyen başarı semantiği guard oluşturmaz.
6. Indirect jump `UNKNOWN_CONTROL_FLOW` üretir.
7. Entitlement object dönüşünün `boolValue` ile test edilmesi ayrı ilişki olarak
   doğrulanır.

### Capability/LPE testleri

1. Binary-wide `STRONG` validation operasyon guard'ı sayılmaz.
2. `sandbox_check*` yalnız başına `STRONG` authorization üretmez.
3. Sandboxed ve unsandboxed profiller farklı policy path alır.
4. Kontrollü path üzerinden `fchown` `CONTROLLED_SINK` üretir.
5. Hedef kapsamı bilinmiyorsa `resource_authorization=UNKNOWN` kalır.
6. Guard eklenmiş fixture'da operation authorization scope yükselir.
7. Kontrollü sink otomatik olarak `PRIMITIVE` veya `IMPACT` olmaz.

### CVE davranış fixture'ları

Savunmasız davranış fixture'ı:

```text
sandbox predicate
  -> allowlist includes RepairPermissionsForCloudItems
  -> Paths input
  -> open(path)
  -> fchown(fd, caller_uid, existing_gid)
  -> no operation-specific entitlement guard
  -> no allowed-root guard
```

Beklenen sonuç: yüksek araştırma öncelikli, kontrollü privileged ownership sink;
operation ve resource authorization çözülmemiş; exploitability kanıtlanmamış.

Düzeltilmiş davranış fixture'ı:

```text
RepairPermissionsForCloudItems handler
  -> com.apple.private.desktopservices.cloud-repair-perm check
  -> reject branch on missing entitlement
  -> open(path)
  -> fchown(fd, ...)
```

Beklenen sonuç: entitlement kontrolü `AUTHORIZATION_GUARDS_SINK`; path kapsamı
halen yoksa resource authorization ayrı biçimde çözülmemiş kalır.

### Tam doğrulama

```bash
python3 -m unittest discover -s tests -t tests -v
python3 tbm.py --help
python3 tbm.py scan --json > /tmp/tbm-plan-validation.json
```

Tam scan yalnızca statik çalıştırılacak. Sonuçlarda şu karşılaştırmalar alınacak:

- toplam operation/capability/LPE finding sayısı;
- `UNKNOWN_*` dağılımı;
- `CONTROLLED_SINK` sayısındaki değişim;
- operation guard sayısı ve negatif testlerde false promotion olup olmadığı;
- ilk 50 araştırma hedefindeki sıralama değişimi;
- scan süresi ve report boyutu.

## Kabul ölçütleri

Plan tamamlanmış sayılacak ancak aşağıdakilerin tümü sağlandığında:

1. XPC operation ve handler bağı kanıt seviyesiyle raporlanıyor.
2. Caller identity, operation authorization ve resource authorization ayrılmış.
3. `sandbox_check*` binary varlığı güvenli/strong operation guard gibi görünmüyor.
4. Guard kararı dominance, branch sonucu ve failure-path reachability içeriyor.
5. `open(path) -> fchown(fd)` zinciri descriptor provenance ile görünür.
6. Savunmasız fixture güçlü araştırma adayı üretirken exploit hükmü vermiyor.
7. Düzeltilmiş fixture entitlement guard'ını doğru operasyona bağlıyor.
8. Bütün yeni `UNKNOWN_*` nedenleri rapor çıktılarında korunuyor.
9. Standart kütüphane dışında zorunlu yeni bağımlılık eklenmiyor.
10. Tam unittest paketi geçiyor ve statik scan önce/sonra metrikleri inceleniyor.

## Uygulama sırası ve PR bölümü

Değişiklikleri tek büyük commit yerine şu sırayla küçük, incelenebilir parçalara
ayırmak uygun olur:

1. IPC string/key ve operation modelleme + testler.
2. Caller profile ve policy path modelleme + testler.
3. Fail-closed CFG operation guard analizi + negatif testler.
4. Descriptor provenance + LPE/resource authorization modeli + testler.
5. Raporlama, sıralama ve tam scan karşılaştırması.

Her parça kendi testlerini taşımalı. Şema alanları eklenirken mevcut JSON
tüketicilerinin uyumluluğu korunmalı; gerekirse schema version artırılmalı ve
uyumluluk notu eklenmeli.

## Başlıca riskler

- C++ table ve block callback çözümü çok fazla `UNKNOWN_INDIRECT_HANDLER`
  üretebilir. Bu kabul edilebilir; yanlış handler bağı üretmekten iyidir.
- ObjC/Swift dispatch tam çözülemez. Belirsizlik named `UNKNOWN_*` olarak
  korunmalı.
- CFG analizi exception ve indirect edge'leri eksik görebilir. Bu durumlarda
  guard promotion yapılmamalı.
- Descriptor alias takibi state explosion yaratabilir. Fonksiyon derinliği,
  ziyaret ve fact bütçeleri korunmalı; bütçe aşımı raporlanmalı.
- Genel XPC key toplama raporları büyütebilir. Yalnızca API/callsite/table ile
  bağlanan string'ler modele alınmalı.
- macOS sürümleri arasında binary şekli değişir. Fixture testleri adreslere veya
  tek bir daemon adına bağımlı olmamalı.

## Beklenen nihai DesktopServicesHelper çıktısı

Başarılı uygulamadan sonra benzer bir savunmasız binary için hedeflenen özet:

```text
Operation: RepairPermissionsForCloudItems
Input: XPC data key "Paths"
Caller profile: SANDBOXED; Mach lookup capability CONDITIONAL/UNKNOWN
Handler relationship: PROVEN or INFERRED with address evidence
Sink: fchown
Target provenance: Paths -> open(path) -> descriptor -> fchown(fd)
Identity verification: observed/recovered scope
Operation authorization: not proven for this caller profile
Resource authorization: UNKNOWN; allowed-root guard not proven
Maturity: CONTROLLED_SINK
Research priority: HIGH
Exploitability: not established
Next step: verify dispatcher/handler policy and allowed resource scope manually
```

Bu çıktı araştırmacıyı doğru handler ve doğru güven sınırına taşır; aracın statik
kanıt sınırını aşmadan CVE-2026-43783 sınıfındaki hataları görünür kılar.
