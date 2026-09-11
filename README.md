# yu-glucose

Sibionics / SISENSING GS3 CGM 을 제조사 앱 없이 직접 BLE 로 읽기 위한 조사·구현 저장소.

- `docs/gs3-ble-protocol-analysis.md` — Juggluco 등 공개 소스를 추적해 정리한 GS3 BLE 프로토콜 분석 (연결 절차, RC4 암호화, 패킷 구조, 계정 바인딩, 혈당 파싱, 캡처 계획).
- `tools/gs3_protocol.py` — 위 분석의 파이썬 참조 구현. `python3 tools/gs3_protocol.py selftest` / `vectors` / `decrypt <hex>` / `simulate`.
- `docs/gs3/index.html` — Web Bluetooth 기반 임시 뷰어 (iPhone 은 Bluefy 브라우저, Android/PC 는 Chrome). GitHub Pages `/docs` 로 서빙: `https://amidiot.github.io/yu-glucose/gs3/`.
