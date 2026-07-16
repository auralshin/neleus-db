//! std-only parallel map over owned items; preserves order.

use std::sync::Mutex;

/// Run `f` over `items` on up to `available_parallelism` scoped threads.
/// Falls back to sequential for tiny inputs where spawn cost dominates.
pub(crate) fn parallel_map<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let n = items.len();
    let workers = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
        .min(n);
    if workers <= 1 || n < 16 {
        return items.into_iter().map(f).collect();
    }

    let queue: Mutex<std::vec::IntoIter<(usize, T)>> = Mutex::new(
        items
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
            .into_iter(),
    );
    let mut out: Vec<Option<R>> = (0..n).map(|_| None).collect();
    let slots = Mutex::new(&mut out);

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let next = queue.lock().expect("queue poisoned").next();
                    let Some((i, item)) = next else { break };
                    let r = f(item);
                    slots.lock().expect("slots poisoned")[i] = Some(r);
                }
            });
        }
    });

    out.into_iter()
        .map(|r| r.expect("worker filled every slot"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_order_and_completeness() {
        let items: Vec<u64> = (0..1000).collect();
        let out = parallel_map(items, |x| x * 2);
        assert_eq!(out.len(), 1000);
        for (i, v) in out.iter().enumerate() {
            assert_eq!(*v, (i as u64) * 2);
        }
    }

    #[test]
    fn tiny_inputs_run_sequentially() {
        assert_eq!(parallel_map(vec![1, 2, 3], |x| x + 1), vec![2, 3, 4]);
    }
}
