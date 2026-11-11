# KakaoTalk Adblocker (macOS)

macOS용 카카오톡(KakaoTalk) 채팅 목록 하단의 광고 배너를 제거하는 도구입니다.
앱 바이너리에서 "광고를 표시할지" 판단하는 함수를 찾아 항상 "표시 안 함"을 반환하도록 패치하고, 다시 서명해 설치합니다.

> ⚠️ 카카오(Kakao)와 무관한 비공식 개인용 도구입니다. 앱을 수정·재서명하므로 본인 책임하에 사용하세요.

## 동작 방식

카카오톡은 광고 서버 차단만으로는 자체 홍보 배너가 대신 떠서 완전히 사라지지 않습니다. 그래서 바이너리를 직접 패치합니다.

- 광고 표시 여부는 `FSMainViewController.updateAdvertise` 가 호출하는 함수(내부적으로 `isCountryISOKorea` 를 확인)가 결정합니다.
- 이 함수를 `mov w0, #0; ret` (항상 false) 로 바꿔 배너가 그려지지 않게 합니다. 광고 영역만 숨기므로 채팅 등 다른 기능에는 영향이 없습니다.
- 함수 주소를 고정하지 않고 **매 실행마다 자동으로 탐색**하므로, 앱 업데이트로 주소가 바뀌어도 그대로 다시 실행하면 됩니다.
- 패치 후 Hardened Runtime 을 제외하고 ad-hoc 서명으로 다시 서명합니다. 권한(entitlements)은 원본에서 그대로 추출해 적용합니다.

## 요구 사항

- Apple Silicon(arm64) Mac
- Python 3 (macOS 기본 포함)
- Xcode Command Line Tools (`codesign`, `ditto` 등)
- App Store 에서 설치한 카카오톡 (`/Applications/KakaoTalk.app`)
- 설치 단계에서 관리자 비밀번호 입력 (GUI 창)

## 사용법

```sh
# 광고 제거 적용 (분석 → 백업 → 패치 → 서명 → 검증 → 설치 → 확인)
python3 adblock.py

# 현재 상태 확인 (설치본 / 백업 / 빌드)
python3 adblock.py status

# 원본(카카오 서명)으로 복원
python3 adblock.py restore

# 특정 실행 파일에서 광고 판단 함수만 탐색
python3 adblock.py analyze <executable>
```

옵션:

- `--force` — 이미 적용돼 있어도 다시 빌드·설치
- `--no-install` — 빌드·검증까지만 하고 설치는 생략

각 단계는 실행 전에 상태를 검사해 이미 끝난 단계는 건너뛰고, 예상과 다르면(버전이 크게 바뀌는 등) 아무것도 바꾸지 않고 멈춥니다.

## 백업과 복원

- 최초 실행 시 원본 앱을 버전별로 `backup/KakaoTalk-<버전>.app` 에 백업합니다.
- 언제든 `python3 adblock.py restore` 로 원본으로 되돌릴 수 있습니다.

## 주의 사항

- **App Store 업데이트 시 패치가 사라집니다.** 업데이트 후 `python3 adblock.py` 를 다시 실행하세요.
- 앱을 수정·재서명하므로, 카카오 서버 측에서 변조를 감지할 가능성을 배제할 수 없습니다.
- 지금까지 카카오톡 **26.9.0** 에서 확인했습니다. 다른 버전에서는 자동 탐색이 실패하면 안전하게 중단됩니다.

## 디렉토리 구성

```
kakaotalk_adblocker/
├── adblock.py                     # 메인 스크립트 (분석·패치·서명·설치·복원)
├── backup/
│   └── KakaoTalk-26.9.0.app       # 원본 앱 백업
└── README.md
```
