#![cfg(unix)]

use std::io::Error;
use std::path::Path;

use anyhow::{Result, anyhow};
use neleus_db::Database;
use tempfile::TempDir;

fn make_pipe() -> Result<[libc::c_int; 2]> {
    let mut fds = [0; 2];
    // SAFETY: `pipe` initializes the provided 2-int array on success.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(anyhow!("pipe failed: {}", Error::last_os_error()));
    }
    Ok(fds)
}

fn close_fd(fd: libc::c_int) {
    // SAFETY: Closing an fd is safe; errors are ignored in cleanup paths.
    let _ = unsafe { libc::close(fd) };
}

fn wait_for_start(read_fd: libc::c_int) -> Result<()> {
    let mut b = [0u8; 1];
    // SAFETY: valid pointers and buffer length are provided.
    let rc = unsafe { libc::read(read_fd, b.as_mut_ptr().cast(), 1) };
    if rc != 1 {
        return Err(anyhow!(
            "read start signal failed: rc={} err={}",
            rc,
            Error::last_os_error()
        ));
    }
    Ok(())
}

fn send_start(write_fd: libc::c_int) -> Result<()> {
    let b = [1u8; 1];
    // SAFETY: valid pointers and buffer length are provided.
    let rc = unsafe { libc::write(write_fd, b.as_ptr().cast(), 1) };
    if rc != 1 {
        return Err(anyhow!(
            "write start signal failed: rc={} err={}",
            rc,
            Error::last_os_error()
        ));
    }
    Ok(())
}

fn wait_child_ok(pid: libc::pid_t) -> Result<()> {
    let mut status: libc::c_int = 0;
    // SAFETY: `waitpid` is called with a child pid and valid status pointer.
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc < 0 {
        return Err(anyhow!("waitpid failed: {}", Error::last_os_error()));
    }

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }

    Err(anyhow!("child {} failed with status {}", pid, status))
}

fn child_exit(result: Result<()>) -> ! {
    let code = if result.is_ok() { 0 } else { 1 };
    // SAFETY: `_exit` terminates child process immediately with code.
    unsafe { libc::_exit(code) }
}

fn open_db(path: &Path) -> Result<Database> {
    Database::open(path)
}

#[test]
fn multiprocess_state_contention_preserves_all_updates() -> Result<()> {
    let tmp = TempDir::new()?;
    let db_root = tmp.path().join("db");
    Database::init(&db_root)?;

    let gate1 = make_pipe()?;
    let gate2 = make_pipe()?;

    // SAFETY: `fork` is called in a test context; child immediately executes isolated logic and exits.
    let pid1 = unsafe { libc::fork() };
    if pid1 < 0 {
        return Err(anyhow!("fork child1 failed: {}", Error::last_os_error()));
    }
    if pid1 == 0 {
        close_fd(gate1[1]);
        close_fd(gate2[0]);
        close_fd(gate2[1]);
        let run = (|| -> Result<()> {
            wait_for_start(gate1[0])?;
            close_fd(gate1[0]);
            let db = open_db(&db_root)?;
            for i in 0..24 {
                let key = format!("a/{i}");
                let value = format!("va-{i}");
                let _ = db.state_set_at_head("main", key.as_bytes(), value.as_bytes())?;
            }
            Ok(())
        })();
        child_exit(run);
    }

    // SAFETY: same as above.
    let pid2 = unsafe { libc::fork() };
    if pid2 < 0 {
        return Err(anyhow!("fork child2 failed: {}", Error::last_os_error()));
    }
    if pid2 == 0 {
        close_fd(gate2[1]);
        close_fd(gate1[0]);
        close_fd(gate1[1]);
        let run = (|| -> Result<()> {
            wait_for_start(gate2[0])?;
            close_fd(gate2[0]);
            let db = open_db(&db_root)?;
            for i in 0..24 {
                let key = format!("b/{i}");
                let value = format!("vb-{i}");
                let _ = db.state_set_at_head("main", key.as_bytes(), value.as_bytes())?;
            }
            Ok(())
        })();
        child_exit(run);
    }

    close_fd(gate1[0]);
    close_fd(gate2[0]);
    send_start(gate1[1])?;
    send_start(gate2[1])?;
    close_fd(gate1[1]);
    close_fd(gate2[1]);

    wait_child_ok(pid1)?;
    wait_child_ok(pid2)?;

    let db = Database::open(&db_root)?;
    let root = db.resolve_state_root("main")?;

    for i in 0..24 {
        let key_a = format!("a/{i}");
        let key_b = format!("b/{i}");
        assert_eq!(
            db.state_store.get(root, key_a.as_bytes())?,
            Some(format!("va-{i}").into_bytes())
        );
        assert_eq!(
            db.state_store.get(root, key_b.as_bytes())?,
            Some(format!("vb-{i}").into_bytes())
        );
    }

    Ok(())
}

#[test]
fn multiprocess_commit_contention_keeps_linear_head_history() -> Result<()> {
    let tmp = TempDir::new()?;
    let db_root = tmp.path().join("db");
    Database::init(&db_root)?;
    let db = Database::open(&db_root)?;
    let _ = db.state_set_at_head("main", b"seed", b"v0")?;

    let gate1 = make_pipe()?;
    let gate2 = make_pipe()?;

    // SAFETY: `fork` is called in a test context; child immediately executes isolated logic and exits.
    let pid1 = unsafe { libc::fork() };
    if pid1 < 0 {
        return Err(anyhow!("fork child1 failed: {}", Error::last_os_error()));
    }
    if pid1 == 0 {
        close_fd(gate1[1]);
        close_fd(gate2[0]);
        close_fd(gate2[1]);
        let run = (|| -> Result<()> {
            wait_for_start(gate1[0])?;
            close_fd(gate1[0]);
            let db = open_db(&db_root)?;
            for i in 0..12 {
                let _ = db.create_commit_at_head("main", "child1", &format!("c1-{i}"), vec![])?;
            }
            Ok(())
        })();
        child_exit(run);
    }

    // SAFETY: same as above.
    let pid2 = unsafe { libc::fork() };
    if pid2 < 0 {
        return Err(anyhow!("fork child2 failed: {}", Error::last_os_error()));
    }
    if pid2 == 0 {
        close_fd(gate2[1]);
        close_fd(gate1[0]);
        close_fd(gate1[1]);
        let run = (|| -> Result<()> {
            wait_for_start(gate2[0])?;
            close_fd(gate2[0]);
            let db = open_db(&db_root)?;
            for i in 0..12 {
                let _ = db.create_commit_at_head("main", "child2", &format!("c2-{i}"), vec![])?;
            }
            Ok(())
        })();
        child_exit(run);
    }

    close_fd(gate1[0]);
    close_fd(gate2[0]);
    send_start(gate1[1])?;
    send_start(gate2[1])?;
    close_fd(gate1[1]);
    close_fd(gate2[1]);

    wait_child_ok(pid1)?;
    wait_child_ok(pid2)?;

    let db = Database::open(&db_root)?;
    let mut count = 0usize;
    let mut cursor = db.refs.head_get("main")?;
    while let Some(hash) = cursor {
        count += 1;
        let commit = db.commit_store.get_commit(hash)?;
        cursor = commit.parents.first().copied();
    }

    assert_eq!(count, 24);
    Ok(())
}
