use super::{fs, Journey};

impl Journey {
    pub(super) fn refused_lock(&mut self, label: &str, pid: &str, host: &str) {
        let lock = self.keyring.join("pubring.kbx.lock");
        let contents = format!("{pid}\n{host}\n");
        fs::write(&lock, &contents).unwrap();
        fs::write(self.root.join(format!("{label}.lock.before")), &contents).unwrap();
        let output = self.skarbiec(label, &["recover-daemons"]);
        let after = fs::read_to_string(&lock).expect("recovery must preserve the unowned lock");
        assert_eq!(after, contents, "{label} changed the unowned lock");
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains(lock.to_str().unwrap()) && diagnostic.contains(pid),
            "{label} omitted the observed lock and process identity: {diagnostic}"
        );
        fs::write(self.root.join(format!("{label}.lock.after")), after).unwrap();
        fs::remove_file(lock).unwrap();
    }
}
