# Dataset: NSL-KDD

Locked in Phase 0 as the dataset for MLShield's network-intrusion-detection framing.

## Why NSL-KDD

- Well-known, well-documented benchmark for network intrusion detection.
- Small enough (~23 MB total) to version and hash reliably without external storage.
- Labeled attack categories map cleanly onto data-poisoning experiments in later phases
  (Phase 5+): we can inject/flip labels in a controlled way and measure detector recall.
- Widely cited in academic MLOps/security coursework, so results are checkable against
  published baselines.

CICIDS2017 was considered (closer to a modern traffic capture) but requires a large,
authenticated download from the Canadian Institute for Cybersecurity site and is far
larger (~50 GB raw), which is impractical for reproducible git/DVC versioning in this
project's timeline. NSL-KDD is the pragmatic, locked choice for the MVP; a switch to
CICIDS2017 is explicitly out of scope after this phase (scope lock).

## Source

- `KDDTrain+.txt` and `KDDTest+.txt`, fetched from the NSL-KDD mirror:
  https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/
- Original dataset: Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. (2009).
  "A Detailed Analysis of the KDD CUP 99 Data Set", published by the University of
  New Brunswick Canadian Institute for Cybersecurity (UNB CIC). Public benchmark
  dataset, free for research use.

## Integrity (locked at Phase 0)

```
sha256sum data/raw/KDDTrain+.txt
1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95  KDDTrain+.txt

sha256sum data/raw/KDDTest+.txt
fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84  KDDTest+.txt
```

If these hashes ever change, the raw files were re-fetched/modified — re-verify
against the upstream source before trusting any downstream result.

## Shape

- `KDDTrain+.txt`: 125,973 rows
- `KDDTest+.txt`: 22,544 rows
- 41 features + 1 label column (`normal` or an attack name) + 1 `difficulty` column
  (no header row in the raw files; column names are defined in
  `src/data/load_dataset.py`).

## License / usage note

NSL-KDD is a public research benchmark distributed for academic use. No PII;
synthetic/simulated network traffic. Safe to commit directly to this repo.
