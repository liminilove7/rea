"""Verify saved report references and make a hash-checked local evidence backup."""
import hashlib
import json
import pathlib
import shutil
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

root = pathlib.Path(__file__).resolve().parent
report = root.parent / 'aion-autocombat-20261021/实体与技能调用链进展.html'
text = report.read_text('utf-8')
section = text.split('<!-- HEALTH-STOP-EVIDENCE-BEGIN -->', 1)[1].split('<!-- HEALTH-STOP-EVIDENCE-END -->', 1)[0]

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.links.extend(value for key, value in attrs if key == 'href')

parser = Links()
parser.feed(section)
if '<!-- RETAINED-CORPSE-BEGIN -->' in text:
    parser.feed(text.split('<!-- RETAINED-CORPSE-BEGIN -->', 1)[1].split('<!-- RETAINED-CORPSE-END -->', 1)[0])
checks = []
for link in parser.links:
    parsed = urlsplit(link)
    assert not parsed.scheme and not parsed.netloc, link
    target = (report.parent / unquote(parsed.path)).resolve()
    checks.append(dict(href=link, exists=target.is_file()))
assert checks and all(c['exists'] for c in checks)
assert text.count('id="health-stop-evidence-20261024"') == 1
assert 'LIVE-REA-HEALTH-BEGIN' in text
assert '预检目标是灰毛布拉斯' in section and '亞希爾瀾號船員' in section
qa = dict(localLinks=checks, sectionUnique=True, priorSectionPreserved=True,
          visualReview='Not performed: browser URL policy rejected file protocol; no workaround attempted.')
(root/'health-stop-report-validation.json').write_text(json.dumps(qa, ensure_ascii=False, indent=2), encoding='utf-8')

files = set(root.glob('health-stop*.json'))
files.update(root.glob('rea-health-2026-10-24T11-*/*'))
for name in ['capture_health_stop.py', 'record_health_stop_results.py', 'finalize_health_stop.py',
             'run-rea-health-batch.mjs', 'attach_health_stop_readonly.py', 'report-before-health-stop.html',
             'record_retained_corpse.py']:
    files.add(root/name)
files.add(report)
destination = root.parent/'aion-report-backup/aion-tw-20261019/health-stop-20261024'
manifest = []
for source in sorted(files):
    if not source.is_file():
        continue
    relative = source.relative_to(root.parent)
    target = destination/relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert hashlib.sha256(target.read_bytes()).hexdigest() == digest
    manifest.append(dict(path=relative.as_posix(), bytes=source.stat().st_size, sha256=digest))
(destination/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(dict(linksVerified=len(checks), backupFiles=len(manifest), destination=str(destination)), ensure_ascii=False))
