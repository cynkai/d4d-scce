# D4D T2 #12 — 데이터 스키마 계약서

방산 공급망 자격증명 노출 조기경보. 세 개의 raw 신호 소스로 파이프라인을 구동한다.
**데이터는 raw 신호만 담는다. 위험 점수는 스코어링 엔진이 계산한다.** (관심사 분리)

기준일(TODAY) = `2026-07-04`. 시드 고정 → 데모 재현 가능.

---

## 1. `vendors.json` — 협력사 자산 인벤토리

매칭의 기준점. 유출/스틸러 신호를 이 도메인 목록에 상관시킨다.

| 필드 | 타입 | 의미 |
|---|---|---|
| `vendor_id` | str | `V001`… 고유 ID |
| `name` | str | 회사명 (전부 가공) |
| `tier` | int | 1=1차, 2=2차. **말단(2차)일수록 표적** — 배경 반영, 가중 가능 |
| `domains` | [str] | 이메일/웹 도메인. 매칭 키 |
| `criticality` | str | 공급 품목 임무 중요도 → **impact 가중**에 사용 |
| `employees` | int | 규모(노출 표면 참고) |

## 2. `leaked_credentials.json` — 유출 자격증명

콤보리스트/브리치/다크웹에 떠도는 email:password. **낮은 강도 신호**(오래됨·정적).

| 필드 | 타입 | 의미 |
|---|---|---|
| `record_id` | str | `L00001`… |
| `email` / `domain` | str | 도메인이 매칭 키 |
| `vendor_id` | str\|null | 매칭된 협력사. null=노이즈(비협력사) |
| `is_corporate` | bool | 협력사 도메인 여부 |
| `password_type` | `plaintext`\|`hash` | 평문이면 즉시 악용 가능 → 가중↑ |
| `source` | str | `combolist:*` / `breach:*` / `darkweb_forum:*` / `telegram_channel:*` |
| `first_seen` | date | 최초 관측일. **최근일수록 가중↑** |

## 3. `stealer_logs.json` — 인포스틸러 감염기기 로그

**핵심 신호원.** 감염된 실기기에서 통째로 털린 자격증명. 활성 침해의 직접 증거.

| 필드 | 타입 | 의미 |
|---|---|---|
| `log_id` | str | `S00001`… |
| `stealer_family` | str | RedLine/Lumma/Vidar/StealC/Raccoon |
| `infection_date` | date | 감염일. **최근일수록 활성 위험↑** |
| `machine_id` | str | 감염 단말 식별자 |
| `country` | str | KR 등 |
| `vendor_id` | str\|null | 매칭 협력사 |
| `is_corporate` | bool | 회사 자격증명 포함 여부 |
| `active_compromise` | bool | **파생 신호** — 회사 도메인 + HIGH 카테고리 유출 시 true |
| `credentials` | [obj] | 이 기기가 흘린 자격증명 목록 |

`credentials[]` 항목:

| 필드 | 의미 |
|---|---|
| `url` | 유출된 로그인 URL |
| `category` | 서비스 분류 (아래) |
| `username` | 계정 |
| `password_type` | 스틸러는 통상 `plaintext` |

### category 심각도 (스코어링 입력)

- **HIGH (활성 침해 신호):** `vpn`, `sso`, `admin_panel`, `cloud_console`, `code_repo`
  → 협력사 내부망 직접 진입 가능. 최근 감염 + HIGH = **즉시 조치 권고 트리거**.
- **LOW:** `webmail`, `saas`, `generic`

---

## 스코어링 엔진이 소비하는 방식 (다음 단계 = 아키텍처)

업체별 위험점수 = 대략 아래 신호의 가중합:

```
risk(vendor) =
      w1 * (유출 크리덴셜 수, 최근·평문 가중)
    + w2 * (스틸러 감염기기 수)
    + w3 * (활성 침해 = 최근 HIGH 카테고리 유출)   <-- 가장 큰 가중
    + w4 * (criticality / tier 임무 영향)
```

`active_compromise == true` 이고 `infection_date`가 최근이면 위험을 급상승시키고
**즉시 조치 권고 통보문**을 자동 생성한다. (히어로 케이스: V007 태성회로)

> `active_compromise`는 데모 편의를 위해 데이터에 미리 표기돼 있지만,
> 스코어링 엔진은 `credentials[].category` + `infection_date`를 직접 보고
> 재계산하는 게 정석이다. 그래야 "우리가 판정한다"가 성립.
