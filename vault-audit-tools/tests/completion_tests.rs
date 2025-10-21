/// Integration tests for shell completion generation
use std::process::Command;

#[test]
fn test_generate_completion_bash() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "generate-completion", "bash"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify bash completion script structure
    assert!(
        stdout.contains("_vault-audit()"),
        "Should contain bash completion function"
    );
    assert!(
        stdout.contains("COMPREPLY"),
        "Should contain bash completion COMPREPLY"
    );
    assert!(
        stdout.contains("complete -F _vault-audit"),
        "Should contain completion registration"
    );

    // Verify all major commands are present
    assert!(
        stdout.contains("entity-churn"),
        "Should include entity-churn command"
    );
    assert!(
        stdout.contains("entity-creation"),
        "Should include entity-creation command"
    );
    assert!(
        stdout.contains("generate-completion"),
        "Should include generate-completion command"
    );
    assert!(
        stdout.contains("kv-analyzer"),
        "Should include kv-analyzer command"
    );
}

#[test]
fn test_generate_completion_zsh() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "generate-completion", "zsh"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify zsh completion script structure
    assert!(
        stdout.contains("#compdef vault-audit"),
        "Should contain zsh compdef header"
    );
    assert!(
        stdout.contains("_vault-audit()"),
        "Should contain zsh completion function"
    );
    assert!(stdout.contains("_arguments"), "Should use zsh _arguments");

    // Verify commands are present
    assert!(
        stdout.contains("entity-churn"),
        "Should include entity-churn command"
    );
    assert!(
        stdout.contains("entity-creation"),
        "Should include entity-creation command"
    );
}

#[test]
fn test_generate_completion_fish() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "generate-completion", "fish"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify fish completion script structure
    assert!(
        stdout.contains("complete -c vault-audit"),
        "Should contain fish completion commands"
    );

    // Verify commands are present
    assert!(
        stdout.contains("entity-churn"),
        "Should include entity-churn command"
    );
    assert!(
        stdout.contains("entity-creation"),
        "Should include entity-creation command"
    );
}

#[test]
fn test_generate_completion_powershell() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "generate-completion", "powershell"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify powershell completion script contains expected content
    assert!(
        !stdout.is_empty(),
        "PowerShell completion should not be empty"
    );
    assert!(
        stdout.contains("vault-audit") || stdout.contains("Register-ArgumentCompleter"),
        "Should contain PowerShell completion content"
    );
}

#[test]
fn test_generate_completion_elvish() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "generate-completion", "elvish"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify elvish completion script contains expected content
    assert!(!stdout.is_empty(), "Elvish completion should not be empty");
    assert!(
        stdout.contains("vault-audit") || stdout.contains("edit:completion:arg-completer"),
        "Should contain Elvish completion content"
    );
}

#[test]
fn test_all_commands_in_completion() {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "generate-completion", "bash"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify all 16 commands are present in completion
    let commands = vec![
        "kv-analyzer",
        "kv-compare",
        "kv-summary",
        "system-overview",
        "token-operations",
        "token-export",
        "token-lookup-abuse",
        "entity-gaps",
        "entity-timeline",
        "path-hotspots",
        "k8s-auth",
        "airflow-polling",
        "preprocess-entities",
        "entity-creation",
        "entity-churn",
        "client-activity",
        "entity-list",
        "generate-completion",
    ];

    for cmd in commands {
        assert!(
            stdout.contains(cmd),
            "Completion should include command: {}",
            cmd
        );
    }
}
