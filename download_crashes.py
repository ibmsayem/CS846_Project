#!/usr/bin/env python3
"""Fetch crash UUIDs from Socorro SuperSearch, download full ProcessedCrash JSON, store as JSONL."""

#

import argparse, json, logging, os, random, time
from datetime import datetime, timedelta
from pathlib import Path
import requests

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

API = "https://crash-stats.mozilla.org/api"
SUPERSEARCH_URL = f"{API}/SuperSearch/"
MAX_WINDOW = 10_000


def backoff(base, attempt):
    return base * 2**attempt * (0.5 + random.random())


def retry_get(session, url, params, timeout, retries, base):
    for i in range(retries + 1):
        try:
            r = session.get(url, params=params, timeout=timeout)
            if r.status_code in (429, 500, 502, 503, 504) and i < retries:
                wait = backoff(base, i)
                if r.status_code == 429 and (ra := r.headers.get("Retry-After")):
                    try: wait = max(wait, float(ra))
                    except: pass
                log.warning("HTTP %s, retry %d/%d, sleep %.1fs", r.status_code, i+1, retries, wait)
                time.sleep(wait)
                continue
            return r
        except requests.RequestException as e:
            if i < retries:
                wait = backoff(base, i)
                log.warning("Error: %s, retry %d/%d, sleep %.1fs", e, i+1, retries, wait)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("unreachable")

# The output line format should be:
# {"uuid": "...", "ok": true/false, "http_status": ..., "error": "...", "processed_crash": {...} or null}
def fetch_crash(session, uuid, timeout, retries, base):
    try:
        r = retry_get(session, f"{API}/ProcessedCrash/", {"crash_id": uuid}, timeout, retries, base)
        if r.status_code != 200:
            return {"uuid": uuid, "ok": False, "http_status": r.status_code, "error": r.text[:300], "processed_crash": None}
        return {"uuid": uuid, "ok": True, "http_status": 200, "error": "", "processed_crash": r.json()}
    except Exception as e:
        return {"uuid": uuid, "ok": False, "http_status": 0, "error": str(e), "processed_crash": None}


def uuids_iteration(session, start, end, product, per_page, max_n, sort,
               by_day, by_hour, window_hours, max_per_day, ss_timeout, ss_sleep, retries, base):
    def page_range(rs, re, limit):
        page, got = 1, 0
        while page <= max(1, MAX_WINDOW // max(1, per_page)):
            params = {"date": [f">={rs}", f"<{re}"], "per_page": per_page, "page": page, "_sort": sort}
            if product: params["product"] = product
            while True:
                try:
                    data = retry_get(session, f"{API}/SuperSearch/", params, ss_timeout, retries, base)
                    data.raise_for_status(); data = data.json(); break
                except KeyboardInterrupt: raise
                except: time.sleep(base * (0.5 + random.random()))
            hits = data.get("hits", [])
            if not hits: return
            if page == 1: log.info("SuperSearch: %d hits (total=%s) %s..%s", len(hits), data.get("total", 0), rs, re)
            for h in hits:
                if uid := (h.get("uuid") or "").strip():
                    yield uid; got += 1
                    if limit and got >= limit: return
            if ss_sleep > 0: time.sleep(ss_sleep)
            if got >= data.get("total", 0): return
            page += 1

    total = 0
    def counted(gen):
        nonlocal total
        for u in gen:
            yield u; total += 1
            if max_n and total >= max_n: return
    
    # downaload by hour or day to avoid hitting the 10k limit, with optional max per day; if neither, do one big query (which may miss some if >10k)

    if by_hour:
        s, e = datetime.fromisoformat(start.replace("Z","")), datetime.fromisoformat(end.replace("Z",""))
        while s < e:
            n = min(e, s + timedelta(hours=window_hours))
            fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S")
            yield from counted(page_range(fmt(s), fmt(n), None)); s = n
            if max_n and total >= max_n: return
    # download by day
    elif by_day:
        s, e = datetime.strptime(start, "%Y-%m-%d"), datetime.strptime(end, "%Y-%m-%d")
        while s < e:
            n = s + timedelta(days=1)
            yield from counted(page_range(s.strftime("%Y-%m-%d"), n.strftime("%Y-%m-%d"), max_per_day)); s = n
            if max_n and total >= max_n: return
    else:
        yield from counted(page_range(start, end, None))


def load_done(path):
    if not path.exists(): return set()
    done = set()
    for line in path.read_text().splitlines():
        try: done.add(json.loads(line)["uuid"])
        except: pass
    return done

# Main download function: parse args, set up session, iterate UUIDs, fetch crashes, write output, handle retries and logging.
# The output is a JSONL file with one line per crash, containing the UUID, success status, HTTP status, error message if any, and the full ProcessedCrash JSON if successful.
def main():
    p = argparse.ArgumentParser(description="Download ProcessedCrash JSON from Socorro.")
    a = p.add_argument
    a("--start-date", default="2025-12-01"); a("--end-date", default="2026-02-01")
    a("--product", default="Firefox"); a("--output", default="processed_crashes.jsonl")
    a("--sort", choices=["date","-date"], default="date")
    a("--by-day", action="store_true"); a("--by-hour", action="store_true", default=True)
    a("--no-by-hour", dest="by_hour", action="store_false")
    a("--window-hours", type=int, default=1); a("--max-per-day", type=int)
    a("--max-crashes", type=int); a("--api-token", default=os.environ.get("SOCORRO_API_TOKEN"))
    a("--sleep", type=float, default=2.0); a("--timeout", type=float, default=30.0)
    a("--ss-timeout", type=float); a("--ss-sleep", type=float, default=1.0)
    a("--max-retries", type=int, default=3); a("--backoff-base", type=float, default=2.0)
    a("--per-page", type=int, default=100); a("--overwrite", action="store_true")
    args = p.parse_args()

    out = Path(args.output)
    if args.overwrite and out.exists(): out.unlink()
    done = load_done(out)
    if done: log.info("Resuming: %d already done", len(done))
    out.parent.mkdir(parents=True, exist_ok=True)

    sess = requests.Session()
    sess.headers["User-Agent"] = "crash-report-fetcher/1.0"
    if args.api_token: sess.headers["Authorization"] = f"Bearer {args.api_token}"

    ok = fail = 0
    ss_to = args.ss_timeout or args.timeout
    with out.open("a") as f:
        for uuid in uuids_iteration(sess, args.start_date, args.end_date, args.product or None,
                               args.per_page, args.max_crashes, args.sort, args.by_day,
                               args.by_hour, args.window_hours, args.max_per_day,
                               ss_to, args.ss_sleep, args.max_retries, args.backoff_base):
            if uuid in done: continue
            rec = fetch_crash(sess, uuid, args.timeout, args.max_retries, args.backoff_base)
            ok, fail = ok + rec["ok"], fail + (not rec["ok"])
            f.write(json.dumps(rec, ensure_ascii=False) + "\n"); f.flush()
            done.add(uuid)
            log.info("[%d] %s %s (ok=%d fail=%d)", ok+fail, uuid, "OK" if rec["ok"] else "FAIL", ok, fail)
            if args.sleep > 0: time.sleep(args.sleep)
    log.info("Done. %d written (ok=%d fail=%d) -> %s", ok+fail, ok, fail, out)


if __name__ == "__main__":
    main()