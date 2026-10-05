# Live — Shubham Safaya's build-in-public hub

**Live:** https://shubham-safaya.github.io/live/

A single public directory of everything I'm building: auto-updating dashboards, daily/weekly automation, open-source tools, and a weekly essay book. Share this one link and someone can browse the whole system.

## How it stays current

`index.html` (one file, no build, no backend) pulls **last-updated stamps live from the GitHub API** in the browser, so the page reflects reality every day with zero maintenance. Live dashboards link straight to their running apps.

## What's listed

- **Live dashboards:** US Consumer Pulse, Mission Control, Job Search Dashboard
- **Automation:** Pre-Market Stock Brief and Evening Career Brief (private — shown without links), The Identity Layer weekly essay, YouTube → Shorts Studio
- **Open source:** identity-resolution-engine, data-quality-monitor, productivity-toolkit, accessibility-alarm, competitive-programming
- **Writing & content:** Medium book, YouTube channel, and a link to the personal portfolio

Private repos (the stock screener and job pipeline, which hold personal data) are shown with a *Private* badge and no link, so the hub stays safe to share publicly.

Built by [Shubham Safaya](https://shubham-safaya.github.io).

## Release radar

A weekly workflow (`.github/workflows/release-radar.yml`) scans every repo's GitHub Actions,
`requirements.txt`, `pyproject.toml` and `package.json`, then keeps one `release-radar` issue up
to date. It flags security fixes, breaking changes, Node runtime moves, yanked or deprecated
releases, new majors your pins can't reach, and `>=` floors that will jump a major on the next
run. Routine patch and minor releases are ignored. A comment is added only when something new
appears, and the issue closes itself when the list is empty.

```bash
python scripts/release_radar.py --sample            # offline demo with fixture data
python scripts/release_radar.py --local ~/code      # scan local clones, print only
python -m unittest discover -s tests                # offline tests
```

Private repos are included only when a `RADAR_TOKEN` secret holds a fine-grained token with
read-only Contents access to all repos. Without it, the radar covers public repos.

