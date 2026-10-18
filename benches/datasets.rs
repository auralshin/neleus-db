//! Retrieval on public datasets. `NELEUS_BENCH_DATA` points at a directory
//! holding `beir/<name>/{corpus,queries}.jsonl` + `beir/<name>/qrels/test.tsv`
//! (BEIR layout) and `ann/<name>.{train,test}.f32` + `ann/<name>.gt.u32`
//! (`u32 rows, u32 cols`, then row-major little-endian data). Prints `[beir]`
//! and `[ann]` lines; run `benches/tools/fetch-datasets.sh` first.
//!
//! BM25 is scored for nDCG@10 against SQLite FTS5 on the same queries; HNSW
//! recall@10 is measured against the dataset's exact neighbours across `ef`.

use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use neleus_db::engine::SearchFilter;
use neleus_db::engine::segment::{ChunkInput, IndexSegment};
use neleus_db::hash::hash_typed;

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

fn summary(mut t: Vec<Duration>) -> String {
    t.sort();
    format!(
        "p50 {:?} p99 {:?}",
        percentile(&t, 0.5),
        percentile(&t, 0.99)
    )
}

fn jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::io::BufReader::new(std::fs::File::open(path).unwrap())
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect()
}

/// nDCG@10 with graded relevance and the standard log2 discount.
fn ndcg10(ranked: &[String], rel: &HashMap<String, u32>) -> f64 {
    let dcg: f64 = ranked
        .iter()
        .take(10)
        .enumerate()
        .map(|(i, d)| f64::from(*rel.get(d).unwrap_or(&0)) / (i as f64 + 2.0).log2())
        .sum();
    let mut ideal: Vec<u32> = rel.values().copied().collect();
    ideal.sort_unstable_by(|a, b| b.cmp(a));
    let idcg: f64 = ideal
        .iter()
        .take(10)
        .enumerate()
        .map(|(i, &g)| f64::from(g) / (i as f64 + 2.0).log2())
        .sum();
    if idcg == 0.0 { 0.0 } else { dcg / idcg }
}

fn beir(dir: &Path, name: &str) {
    let corpus = jsonl(&dir.join("corpus.jsonl"));
    let queries: HashMap<String, String> = jsonl(&dir.join("queries.jsonl"))
        .into_iter()
        .map(|q| {
            (
                q["_id"].as_str().unwrap().to_string(),
                q["text"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let mut qrels: HashMap<String, HashMap<String, u32>> = HashMap::new();
    for line in std::fs::read_to_string(dir.join("qrels").join("test.tsv"))
        .unwrap()
        .lines()
        .skip(1)
    {
        let f: Vec<&str> = line.split('\t').collect();
        let grade: u32 = f[2].parse().unwrap();
        if grade > 0 {
            qrels
                .entry(f[0].to_string())
                .or_default()
                .insert(f[1].to_string(), grade);
        }
    }
    let mut qids: Vec<&String> = qrels.keys().filter(|q| queries.contains_key(*q)).collect();
    qids.sort();

    let ids: Vec<String> = corpus
        .iter()
        .map(|d| d["_id"].as_str().unwrap().to_string())
        .collect();
    let texts: Vec<String> = corpus
        .iter()
        .map(|d| {
            format!(
                "{} {}",
                d["title"].as_str().unwrap_or(""),
                d["text"].as_str().unwrap_or("")
            )
        })
        .collect();

    let start = Instant::now();
    let seg = IndexSegment::build(
        vec![],
        texts
            .iter()
            .enumerate()
            .map(|(i, t)| ChunkInput {
                chunk_hash: hash_typed(b"beir:", format!("{i}").as_bytes()),
                text: t.clone(),
                embedding: None,
                meta: None,
            })
            .collect(),
    );
    let build = start.elapsed();

    let sql = rusqlite::Connection::open_in_memory().unwrap();
    sql.execute_batch("CREATE VIRTUAL TABLE t USING fts5(body);")
        .unwrap();
    let start = Instant::now();
    {
        let tx = sql.unchecked_transaction().unwrap();
        let mut ins = tx
            .prepare("INSERT INTO t(rowid, body) VALUES (?1, ?2)")
            .unwrap();
        for (i, t) in texts.iter().enumerate() {
            ins.execute(rusqlite::params![i as i64, t]).unwrap();
        }
        drop(ins);
        tx.commit().unwrap();
    }
    let sql_build = start.elapsed();
    let mut stmt = sql
        .prepare("SELECT rowid FROM t WHERE t MATCH ?1 ORDER BY bm25(t) LIMIT 10")
        .unwrap();

    let filter = SearchFilter::default();
    let (mut ours, mut theirs) = (0.0, 0.0);
    let (mut t_ours, mut t_theirs) = (Vec::new(), Vec::new());
    for qid in &qids {
        let text = &queries[*qid];
        let start = Instant::now();
        let hits = seg.bm25(text, 10, &filter);
        t_ours.push(start.elapsed());
        let ranked: Vec<String> = hits.iter().map(|h| ids[h.doc as usize].clone()).collect();
        ours += ndcg10(&ranked, &qrels[*qid]);

        // FTS5 implicitly ANDs terms; OR them to match BM25's disjunctive query.
        let terms: Vec<String> = text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| format!("\"{}\"", w.to_lowercase()))
            .collect();
        let start = Instant::now();
        let ranked: Vec<String> = if terms.is_empty() {
            Vec::new()
        } else {
            stmt.query_map([terms.join(" OR ")], |r| r.get::<_, i64>(0))
                .unwrap()
                .map(|r| ids[r.unwrap() as usize].clone())
                .collect()
        };
        t_theirs.push(start.elapsed());
        theirs += ndcg10(&ranked, &qrels[*qid]);
    }
    let n = qids.len() as f64;
    eprintln!(
        "[beir] {name}: {} docs, {} queries; index build ours {build:?}, fts5 {sql_build:?}",
        ids.len(),
        qids.len()
    );
    eprintln!(
        "[beir] {name}: nDCG@10 ours {:.4}, fts5 {:.4}; latency ours {}, fts5 {}",
        ours / n,
        theirs / n,
        summary(t_ours),
        summary(t_theirs)
    );
}

fn matrix<T: Copy>(path: &Path, parse: fn([u8; 4]) -> T) -> (usize, usize, Vec<T>) {
    let raw = std::fs::read(path).unwrap();
    let word = |i: usize| u32::from_le_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
    let (rows, cols) = (word(0), word(1));
    let data = raw[8..]
        .chunks_exact(4)
        .map(|c| parse(c.try_into().unwrap()))
        .collect::<Vec<T>>();
    assert_eq!(data.len(), rows * cols, "{}", path.display());
    (rows, cols, data)
}

fn ann(dir: &Path, name: &str) {
    let (n, dim, train) = matrix(&dir.join(format!("{name}.train.f32")), f32::from_le_bytes);
    let (nq, _, test) = matrix(&dir.join(format!("{name}.test.f32")), f32::from_le_bytes);
    let (_, gk, gt) = matrix(&dir.join(format!("{name}.gt.u32")), u32::from_le_bytes);
    let nq = nq.min(1000);

    let start = Instant::now();
    let seg = IndexSegment::build(
        vec![],
        (0..n)
            .map(|i| ChunkInput {
                chunk_hash: hash_typed(b"ann:", format!("{i}").as_bytes()),
                text: String::new(),
                embedding: Some(train[i * dim..(i + 1) * dim].to_vec()),
                meta: None,
            })
            .collect(),
    );
    eprintln!(
        "[ann] {name}: {n} x {dim}d, graph build {:?}",
        start.elapsed()
    );

    let filter = SearchFilter::default();
    for ef in [10usize, 20, 40, 80, 160, 320, 640] {
        let mut found = 0usize;
        let mut times = Vec::with_capacity(nq);
        for q in 0..nq {
            let query = &test[q * dim..(q + 1) * dim];
            let start = Instant::now();
            let hits = seg.vector_ef(query, 10, &filter, ef);
            times.push(start.elapsed());
            let truth = &gt[q * gk..q * gk + 10];
            found += hits.iter().filter(|h| truth.contains(&h.doc)).count();
        }
        let total: Duration = times.iter().sum();
        eprintln!(
            "[ann] {name}: ef={ef:>4} recall@10 {:.4} qps {:.0} {}",
            found as f64 / (nq * 10) as f64,
            nq as f64 / total.as_secs_f64(),
            summary(times)
        );
    }
}

fn main() {
    let Some(root) = std::env::var_os("NELEUS_BENCH_DATA").map(PathBuf::from) else {
        eprintln!("[datasets] NELEUS_BENCH_DATA unset; run benches/tools/fetch-datasets.sh");
        return;
    };
    // `cargo bench` passes harness flags; only a name filter is meaningful.
    let only: Option<String> = std::env::args().skip(1).find(|a| !a.starts_with('-'));
    let wanted = |n: &str| only.as_deref().is_none_or(|o| n.contains(o));
    for kind in ["beir", "ann"] {
        let Ok(entries) = std::fs::read_dir(root.join(kind)) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter_map(|f| match kind {
                "beir" => Some(f),
                _ => f.strip_suffix(".train.f32").map(str::to_string),
            })
            .collect();
        names.sort();
        for name in names.iter().filter(|n| wanted(n)) {
            match kind {
                "beir" => beir(&root.join("beir").join(name), name),
                _ => ann(&root.join("ann"), name),
            }
        }
    }
}
