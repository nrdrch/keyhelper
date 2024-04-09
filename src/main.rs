use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

fn generate_ssh_key(file_name: &str, passphrase: Option<&str>) {
    let user_profile = match env::var("USERPROFILE") {
        Ok(val) => val,
        Err(_) => {
            print_error("Failed to fetch USERPROFILE environment variable.");
            return;
        }
    };

    let private_key_path = format!("{}\\.ssh\\{}", user_profile, file_name);
    let public_key_path = format!("{}.pub", private_key_path);

    if Path::new(&private_key_path).exists() || Path::new(&public_key_path).exists() {
        print_error(&format!(
            "SSH key with the name '{}' already exists. Please choose a different name.",
            file_name
        ));
        return;
    }

    let mut powershell_command = format!("ssh-keygen -t rsa -f \"{}\"", private_key_path);

    if let Some(pass) = passphrase {
        if !pass.is_empty() {
            powershell_command.push_str(&format!(" -N \"{}\"", pass));
        }
    } else {
        powershell_command.push_str(" -N -");
    }

    let output = Command::new("powershell")
        .arg("-Command")
        .arg(&powershell_command)
        .output()
        .expect("Failed to execute PowerShell command");

    if output.status.success() {
        print_success(&format!("SSH key '{}' generated successfully.", file_name));
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        print_error(&format!("Error generating SSH key: {}", error_message));
    }
}

fn remove_ssh_key(file_name: &str) {
    let user_profile = match env::var("USERPROFILE") {
        Ok(val) => val,
        Err(_) => {
            print_error("Failed to fetch USERPROFILE environment variable.");
            return;
        }
    };

    let private_key_path = format!("{}\\.ssh\\{}", user_profile, file_name);
    let public_key_path = format!("{}.pub", private_key_path);

    if !Path::new(&private_key_path).exists() && !Path::new(&public_key_path).exists() {
        print_error(&format!(
            "SSH key with the name '{}' does not exist.",
            file_name
        ));
        return;
    }

    let powershell_command = format!(
        r#"Remove-Item "{}"; Remove-Item "{}""#,
        private_key_path, public_key_path
    );

    let output = Command::new("powershell")
        .arg("-Command")
        .arg(&powershell_command)
        .output()
        .expect("Failed to execute PowerShell command");

    if output.status.success() {
        print_success(&format!(
            "SSH key '{}' and its public key removed successfully.",
            file_name
        ));
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        print_error(&format!("Error removing SSH keys: {}", error_message));
    }
}

fn list_files_in_dir() {
    let user_profile = match env::var("USERPROFILE") {
        Ok(val) => val,
        Err(_) => {
            print_error("Failed to fetch USERPROFILE environment variable.");
            return;
        }
    };

    let dir_path = format!("{}\\.ssh", user_profile);
    let files = match fs::read_dir(&dir_path) {
        Ok(files) => files,
        Err(err) => {
            print_error(&format!("Error listing files: {}", err));
            return;
        }
    };

    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let mut cs = ColorSpec::new();
    cs.set_fg(Some(Color::Ansi256(42))).set_bold(true);
    stdout.set_color(&cs).unwrap();
    writeln!(&mut stdout, "\n>_SSH Key Helper ").unwrap();
    stdout.reset().unwrap();
    println!("   ______________________________________________________________");
    println!("   Files in directory '{}':", dir_path);

    for file in files {
        if let Ok(file) = file {
            let file_name = file.file_name().into_string().unwrap_or_else(|_| String::from("Invalid filename"));
            let mut cs = ColorSpec::new();
            cs.set_fg(Some(Color::Ansi256(42))).set_bold(true);
            stdout.set_color(&cs).unwrap();
            writeln!(&mut stdout, "   {}", file_name).unwrap();
            stdout.reset().unwrap();
        }
    }
}

fn copy_ssh_key(remote_host: &str, file_name: &str) {
    let user_profile = match env::var("USERPROFILE") {
        Ok(val) => val,
        Err(_) => {
            print_error("Failed to fetch USERPROFILE environment variable.");
            return;
        }
    };

    let public_key_path = format!("{}\\.ssh\\{}.pub", user_profile, file_name);

    if !Path::new(&public_key_path).exists() {
        print_error(&format!("Public key for '{}' does not exist.", file_name));
        return;
    }

    let output = Command::new("ssh-copy-id")
        .arg(&format!("{}@{}", file_name, remote_host))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to execute ssh-copy-id command");

    if output.status.success() {
        print_success(&format!("SSH key copied successfully to {}.", remote_host));
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        print_error(&format!("Error copying SSH key: {}", error_message));
    }
}

fn print_error(message: &str) {
    let mut stderr = StandardStream::stderr(ColorChoice::Always);
    stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red))).unwrap();
    writeln!(&mut stderr, "{}", message).unwrap();
    stderr.reset().unwrap();
}

fn print_success(message: &str) {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green))).unwrap();
    writeln!(&mut stdout, "{}", message).unwrap();
    stdout.reset().unwrap();
}

fn print_usage() {
    let header = ">_SSH Key Helper ";
    
    let cmd_descs = [
        ("-n", "<name>           | generate a new SSH key"),
        ("-p", "<passphrase>     | specify a passphrase for the SSH key (optional)"),
        ("-rm", "<name>           | remove an existing SSH key"),
        ("-l", "                 | list files in .ssh"),
        ("-c", "<file> <User@IP> | copy SSH key to a remote host"),
    ];

    let footer = "";

    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    let mut cs = ColorSpec::new();
    cs.set_fg(Some(Color::Ansi256(42))).set_bold(true);
    stdout.set_color(&cs).unwrap();
    writeln!(&mut stdout, "\n{}", header).unwrap();
    stdout.reset().unwrap();
    println!("   ______________________________________________________________");
    
    for (cmd, desc) in cmd_descs.iter() {
        let mut cs = ColorSpec::new();
        cs.set_fg(Some(Color::Ansi256(42))).set_bold(true);
        stdout.set_color(&cs).unwrap();
        write!(&mut stdout, "   {:<6}", cmd).unwrap();
        stdout.reset().unwrap();

        let mut cs = ColorSpec::new();
        cs.set_fg(Some(Color::Ansi256(255))).set_bold(true);
        stdout.set_color(&cs).unwrap();
        writeln!(&mut stdout, "{}", desc).unwrap();
        stdout.reset().unwrap();
    }

    let mut cs = ColorSpec::new();
    cs.set_fg(Some(Color::Ansi256(42))).set_bold(true);
    stdout.set_color(&cs).unwrap();
    writeln!(&mut stdout, "{}", footer).unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let flag = &args[1];

    if flag == "-n" {
        let file_name = &args[2];
        let passphrase_index = args.iter().position(|arg| arg == "-p");
        let passphrase = passphrase_index.and_then(|index| args.get(index + 1).map(|s| s.as_str()));
        generate_ssh_key(file_name, passphrase);
    } else if flag == "-rm" {
        let file_name = &args[2];
        remove_ssh_key(file_name);
    } else if flag == "-l" {
        list_files_in_dir();
    } else if flag == "-c" {
        if args.len() < 3 {
            print_error("Usage: -c <SSHKeyFileName> <User@IP>");
            return;
        }
        let remote_host = &args.last().unwrap();
        let ssh_key_name = if args.len() == 4 { args[2].as_str() } else { "" };
        if ssh_key_name.is_empty() {
            list_files_in_dir();
            return;
        }
        let file_name = match remote_host.split('@').nth(0) {
            Some(name) => name,
            None => {
                print_error("Invalid remote host format.");
                return;
            }
        };
        copy_ssh_key(remote_host, file_name);
    } else {
        print_error("Invalid command. See usage:");
        print_usage();
    }
}
