# Third-party notices

**Vendiant** is released under the [MIT License](LICENSE) (Copyright Deriv). The MIT license
covers the code written for this project. The components below keep their own licenses.

## Bundled in this repository

### Sublist3r — `Sublist3r_New/`

- Upstream: https://github.com/aboul3la/Sublist3r (Ahmed Aboul-Ela), includes subbrute
  (https://github.com/TheRook/subbrute)
- License: **GPL-2.0** — full text in [`Sublist3r_New/LICENSE`](Sublist3r_New/LICENSE)
- Locally modified (`subdomains_sub.py`, `enhanced_subdomain_finder.py` and related changes).
  Everything under `Sublist3r_New/` is distributed under GPL-2.0, not MIT.

## Fetched at build time (not in this repository)

### testssl.sh

- Upstream: https://github.com/testssl/testssl.sh
- Pinned: tag `v3.2.5`, commit `4f17be931a9d60f3f987975aea8221f1a8eaf7aa`
  (`TESTSSL_COMMIT` in `Dashboard/Dockerfile`)
- License: **GPL-2.0** — `LICENSE` ships with the fetched copy at `Encryption/LOCAL/testssl.sh/`
- Run as a separate process. Upstream's prebuilt openssl binaries are removed in the image;
  the Debian-packaged `openssl` is used instead.

## Python and JavaScript dependencies

Python dependencies are pinned in `requirements.txt` and `api_layer/requirements.txt`;
JavaScript dependencies in `frontend/package-lock.json`. Regenerate license summaries with:

```bash
python -m venv .venv-notices && .venv-notices/bin/pip install -r requirements.txt pip-licenses
.venv-notices/bin/pip-licenses --format=plain-vertical --with-urls

cd frontend && npx license-checker --production --summary
```

## Attribution

When redistributing source, binaries or container images, include this file, the MIT license
text, and the GPL-2.0 license texts of the components above. Do not remove copyright notices
from bundled or fetched components.
