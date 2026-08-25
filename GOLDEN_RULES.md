# GOLDEN RULES

1. `index.html`을 수정한 뒤에는 항상 `node .claude/skills/page-check/scripts/check_page.js .`와 `node .claude/skills/security-check/scripts/check_security.js .`를 둘 다 돌려서 🔴 0개인지 확인한다.
2. 새 아티스트/곡을 추가할 때는 기존 구조(`artist-card`, `song-title` 등 클래스명)와 패턴을 그대로 따르고 새 컴포넌트를 새로 만들지 않는다.
3. `<img>` 태그에는 항상 `alt` 속성을 채운다.
4. `quotes.txt`에 문구를 추가할 때는 한 줄에 하나씩, 개인정보나 외부 링크 없이 순수 텍스트만 쓴다 (GitHub Actions가 매일 자동으로 `README.md`에 반영한다).
