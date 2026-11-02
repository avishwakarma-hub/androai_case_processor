"""
zintel_client.py — Thin Z-Intel Plus API client for the androAI case processor.
"""

import logging
import os
import zipfile

import requests

logger = logging.getLogger("androai_processor.zintel")


class ZintelClient:

    def __init__(self, cfg):
        self.api_url = cfg["api_url"].rstrip("/")
        self.api_key = cfg["api_key"]
        self.old_url = cfg.get("old_url", "").rstrip("/")
        self.username = cfg.get("username", "")
        self.password = cfg.get("password", "")
        self.source_id = cfg.get("source_id", 2)
        self.timeout = cfg.get("timeout", 60)
        self.verify_ssl = cfg.get("verify_ssl", True)
        self.headers = {
            "accept": "application/json",
            "Authorization": "Api-Key %s" % self.api_key,
        }
        self._legacy_session = None
        self._legacy_cookies = None

    def get_cases_by_prefix(self, researcher_id, prefix, status="assigned", page_size=100):
        """Fetch cases whose name contains *prefix* and have *status*."""
        url = (
            "%s/api/research/cases/?page_size=%d"
            "&caseassignee__assignee_id=%d"
            "&status=%s"
            "&name__icontains=%s"
        ) % (self.api_url, page_size, researcher_id, status, prefix)
        cases = []
        while url:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code != 200:
                logger.error("Failed to fetch cases: %s %s", resp.status_code, resp.text[:500])
                break
            try:
                payload = resp.json()
            except (ValueError, requests.exceptions.JSONDecodeError):
                logger.error(
                    "Non-JSON response fetching cases (prefix=%s): status=%s body=%s",
                    prefix, resp.status_code, resp.text[:300],
                )
                break
            data = payload.get("data", {})
            results = data.get("results", []) if isinstance(data, dict) else []
            cases.extend(results)
            url = data.get("next") if isinstance(data, dict) else None
        logger.info("Found %d case(s) for researcher %s prefix '%s'", len(cases), researcher_id, prefix)
        return cases

    def get_case_samples(self, case_id):
        """Return a list of MD5 strings for all samples in a case."""
        url = "%s/api/research/cases/%s/samples/" % (self.api_url, case_id)
        md5s = []
        while url:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code != 200:
                logger.error("Failed to fetch samples for case %s: %s", case_id, resp.status_code)
                break
            try:
                payload = resp.json()
            except (ValueError, requests.exceptions.JSONDecodeError):
                logger.error("Non-JSON response fetching samples for case %s", case_id)
                break
            data = payload.get("data", payload)
            if isinstance(data, dict):
                results = data.get("results", [])
                url = data.get("next")
            elif isinstance(data, list):
                results = data
                url = None
            else:
                results, url = [], None
            for entry in results:
                md5 = entry.get("md5_checksum") or entry.get("md5") or ""
                if md5:
                    md5s.append(md5)
        logger.info("Case %s has %d sample(s)", case_id, len(md5s))
        return md5s

    def download_samples(self, md5s, dest_dir):
        """Download APKs via bulk endpoint, extract to *dest_dir*."""
        if not md5s:
            return []
        os.makedirs(dest_dir, exist_ok=True)
        url = "%s/api/research/samples/download/bulk/" % self.api_url
        headers = dict(self.headers)
        headers["Content-Type"] = "application/json"
        resp = requests.post(url, headers=headers, json={"checksums": md5s},
                             timeout=max(self.timeout, 300), verify=self.verify_ssl)
        if resp.status_code != 200:
            logger.error("Bulk download failed: %s %s", resp.status_code, resp.text[:500])
            return []
        ct = (resp.headers.get("Content-Type") or "").lower()
        if "application/json" in ct:
            payload = resp.json()
            data = payload.get("data", payload) if isinstance(payload, dict) else {}
            dl_url = None
            if isinstance(data, dict):
                dl_url = data.get("download_url") or data.get("url") or data.get("file_url")
            if dl_url:
                resp = requests.get(dl_url, headers=self.headers,
                                    timeout=max(self.timeout, 300), verify=self.verify_ssl)
                if resp.status_code != 200:
                    logger.error("Download URL fetch failed: %s", resp.status_code)
                    return []
            else:
                logger.warning("Bulk download returned JSON without download URL")
                return []
        zip_path = os.path.join(dest_dir, "samples.zip")
        with open(zip_path, "wb") as fh:
            fh.write(resp.content)
        logger.info("Downloaded %d bytes to %s", len(resp.content), zip_path)
        extracted = []
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Zintel sample ZIPs are password-protected with "infected"
                try:
                    zf.extractall(dest_dir, pwd=b"infected")
                except RuntimeError:
                    # Fallback: try without password (some ZIPs are unprotected)
                    zf.extractall(dest_dir)
                for name in zf.namelist():
                    fp = os.path.join(dest_dir, name)
                    if os.path.isfile(fp):
                        extracted.append(fp)
        except zipfile.BadZipFile as exc:
            logger.error("Failed to extract %s: %s", zip_path, exc)
        logger.info("Extracted %d file(s)", len(extracted))
        return extracted

    def attach_artifact_to_case(self, case_id, artifact_zip_path):
        """Attach a ZIP artifact to an existing Zintel case."""
        url = "%s/api/research/cases/%s/" % (self.api_url, case_id)
        if not os.path.isfile(artifact_zip_path):
            logger.error("Artifact file not found: %s", artifact_zip_path)
            return False
        with open(artifact_zip_path, "rb") as fh:
            files = {"artifacts": (os.path.basename(artifact_zip_path), fh, "application/zip")}
            try:
                resp = requests.patch(
                    url, headers={"Authorization": "Api-Key %s" % self.api_key},
                    files=files, timeout=120, verify=self.verify_ssl,
                )
                if resp.status_code in (200, 201):
                    logger.info("Attached artifact to case %s", case_id)
                    return True
                logger.error("Artifact upload failed: %s %s", resp.status_code, resp.text[:500])
                return False
            except requests.RequestException as exc:
                logger.error("HTTP error attaching artifact: %s", exc)
                return False

    def _legacy_login(self):
        if self._legacy_session is not None:
            return
        if not self.username or not self.password or not self.old_url:
            logger.warning("Legacy login skipped - no credentials")
            return
        self._legacy_session = requests.Session()
        payload = {"username": self.username, "password": self.password}
        resp = self._legacy_session.post(
            "%s/api/login/" % self.old_url, data=payload,
            timeout=self.timeout, verify=self.verify_ssl,
        )
        if not resp or resp.status_code != 200:
            logger.error("Legacy login failed")
            self._legacy_session = None
            return
        self._legacy_cookies = self._legacy_session.cookies
        logger.info("Legacy Zintel login OK for %s", self.username)

    def add_comment_to_case(self, case_id, comment, chunk_size=4000):
        """Add a comment to a Zintel case via the legacy session."""
        if not comment or not comment.strip():
            return
        self._legacy_login()
        if self._legacy_session is None or self._legacy_cookies is None:
            logger.warning("Skipping comment for case %s", case_id)
            return
        url = "%s/add-comment" % self.old_url
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": "%s/case-sample-list/%s" % (self.old_url, case_id),
        }
        chunks = [comment[i: i + chunk_size] for i in range(0, len(comment), chunk_size)]
        for chunk in chunks:
            data = {"comment": chunk, "comment_id": "", "sig_type": "case", "sig_id": str(case_id)}
            resp = self._legacy_session.post(
                url, headers=headers, cookies=self._legacy_cookies,
                data=data, timeout=self.timeout, verify=self.verify_ssl,
            )
            if resp.status_code != 200:
                logger.error("Comment failed for case %s: %s", case_id, resp.status_code)
                return
        logger.info("Added %d comment chunk(s) to case %s", len(chunks), case_id)
