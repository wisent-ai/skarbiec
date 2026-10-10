use super::{fs, Journey};

impl Journey {
    pub(super) fn refused_non_file_vault(&mut self, item: &str) {
        let vault = self.root.join("directory-instead-of-vault");
        fs::create_dir(&vault).expect("create isolated non-file vault path");
        let mut command = self.command(&["get", item, "--field", "value"]);
        command.env("SKARBIEC_VAULT_FILE", &vault);
        let output = self.observe("non-file-vault-read", &mut command);
        assert!(
            !output.status.success(),
            "a directory cannot serve as a vault"
        );
        let detail = String::from_utf8_lossy(&output.stderr);
        assert!(
            detail.contains("read vault file") && detail.contains(vault.to_str().unwrap()),
            "vault read refusal lost its operation or path: {detail}"
        );
        assert!(
            !detail.contains("vault not initialized"),
            "existing unreadable vault was relabeled as missing: {detail}"
        );
        assert!(
            vault.is_dir(),
            "refused read changed the non-file vault path"
        );
        assert!(
            fs::read_dir(&vault).unwrap().next().is_none(),
            "refused read wrote inside the directory"
        );
        let mut maintain = self.command(&["maintain"]);
        maintain
            .env("SKARBIEC_VAULT_FILE", &vault)
            .env_remove("SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB");
        let refused = self.observe("maintenance-multiple-refusals", &mut maintain);
        assert!(
            !refused.status.success(),
            "failed maintenance reported success"
        );
        let detail = String::from_utf8_lossy(&refused.stderr);
        assert!(
            detail.contains("SKARBIEC_GPG_DAEMON_MEMORY_LIMIT_MB")
                && detail.contains("vault is unreadable")
                && detail.contains(vault.to_str().unwrap()),
            "maintenance lost a simultaneous ceiling or readiness failure: {detail}"
        );
        assert!(vault.is_dir(), "maintenance changed the refused vault path");
        assert!(
            fs::read_dir(&vault).unwrap().next().is_none(),
            "refused maintenance wrote inside the directory"
        );
        fs::remove_dir(vault).expect("remove isolated non-file vault path");
    }
}
