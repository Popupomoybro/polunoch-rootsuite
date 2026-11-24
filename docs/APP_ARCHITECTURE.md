# APP_ARCHITECTURE.md — архитектура RootSuite

> Состояние на 24.11.2026. Контрольная рабочая версия: commit `531ba00` (тег `stable-2211-working`), + ветка `hunt-unit6` (49 модулей, ярлыки паник-охоты).

## 1. Состав исходников

| файл | роль |
|---|---|
| `main.m` | `UIApplicationMain` с `@autoreleasepool` |
| `AppDelegate.h/.m` | шелл: окно, список модулей (47/49), dispatch запуска, ROOT-пилюля, `Ave*` API (лог/пост/статус), forensic-файл `rs112477.log`, crash-resumable состояние P2, `RSTextVC` (лог-окно Share/Copy/Close), установщики Sileo/Terminal, AUTO env (`chain`/`name`/`all`/`ROOT`) |
| `Modules.h/.m` | таблица модулей + диспетчер по имени (`RunModule`), плюс модули общего профиля |
| `Root.h/.m` | `RootProbe()` — единственный источник правды о root (geteuid==0 или запись в root-owned путь), `RootStateString()` |
| `Util.h` | макросы (`S(...)` форматирование и пр.) |
| `IsurfUAF.m` | модуль 112477: стадии F (селекторы), G (dup out-shape = оракул чтения), H (маппинг id-qword), K (deref-канарейка), KCE (убраен: свип имён мёртв), P2 (resumable: unit0..6, OOL-спрей, holdGroom), P4 (surface dereq control), `ModIsurfUAFAt(unit)` — прямой вход |
| `Shading5Force.m`, `CGShading.m`, `CVE86950.m`, `MediaRemoteDD.m`, `WorseQuery.m`, `RootPaths*.m`, `KernelPaths.m`, `LastMile.m`, `WebKitProbes.m`, `Scribble.m`, `Unified.m` | исследовательские модули (по одному на вектор/класс дефектов) |
| `JSRun.h` | JSC-скрипты прогонов |
| `Resources/` | Info.plist, entitlements.plist, JSC-скрипты, oracle-PDF (Type-5 shading), dylib-полезная нагрузка |
| `scripts/build.sh` | clang кросс-сборка arm64-apple-ios15.0 **без `-fobjc-arc`** (MRR) — важно для владения памятью (см. DECISION_LOG) |

## 2. Потоки данных

```
[UITextView/UITableView UI]  <-- AveSetStatus / statusChanged
        ^
AppDelegate (модули, dispatch) -- AveLog --> forensic-файл rs112477.log (append, fflush)
        |                             \--> in-memory кольцо (256KB) --> RSTextVC (Share/Copy)
        \-- AvePost --> POST-миррор :8098 (ephemeral-сессия, кап pending 64) [ПК должен быть в LAN]
```

* Лог: **телефон — первичный** (forensic-файл + in-memory кольцо), ПК-сервер — опциональный миррор. Паника/ребут не убивает файл → следующий запуск читает его обратно в Log.
* P2 (112477) пишет `P2KRUN unit/round` **перед** каждым рискованным раундом: паница атрибутируется по раунду, следующий запуск продолжает с него.

## 3. Запуск модуля

`Run` → `_runModules:` (фоновая очередь, QOS_USER_INITIATED) → диспетчер по имени → `ModXxx()` → `AveLog`/`AvePost` → вердикт в лог и статус. Цепочка (`rsRunChain`) выбирает по именам: `112477*` → `112611 force write` → `86950`. Каждый прогон изолирован @try/@catch; исключение не убивает приложение.

## 4. Root-статус

`RootProbe()` (Root.m): `geteuid()==0` или успешная запись в `/private/var/root|/var/root|/`. Никакой другой путь не показывается как ROOTED. UI-пилюля: `ROOTSTATE YES/NO` + живой probe.

## 5. Сборка

CI: `.github/workflows/rootsuite-build.yml` (workflow_dispatch, macos-26-intel) → `scripts/build.sh` → ad-hoc codesign → zip → артефакт `RootSuite-ipa`. Ветки: `master` (стекло, ⚠️ краш на старте), `hunt-unit6` (рабочая база + паник-охота), тег `stable-2211-working`.

## 6. Известные архитектурные долги (и почему не трогаем в рабочей версии)

| долг | почему оставлен |
|---|---|
| MRR без ARC в build.sh | рабочая версия собрана так и работает; перевод на ARC — отдельная задача с полным регрессом (см. DECISION_LOG D-04) |
| 47→49 модулей в одном `buildModules` | монолит, но работает и прозрачно диспатчится; рефактор — после стабилизации редизайна |
| POST-миррор с капом | устройство вне LAN → миррор неполный by design; телефон — первичный лог |
| Стекло на `master` | крашит запуск; возврат планируется поэтапно на базе `hunt-unit6` (табы → материалы → панели), каждая сборка + проверка T1 |