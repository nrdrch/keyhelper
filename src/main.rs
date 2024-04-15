use std::env;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

 

fn main() {

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let flag = &args[1];

    if cfg!(target_os = "windows") {
        
        main_windows(flag);
    } else if cfg!(target_os = "linux") {
        main_linux(flag);
    } else {
        println!("Unsupported operating system.");
    }
}
fn get_os_name() -> String {
    if cfg!(target_os = "windows") {
        "Windows".to_string()
    } else {
        "Linux".to_string()
    }
}

fn get_ssh_dir() -> String {
    if let Ok(ssh_dir) = env::var("HOME") {
        ssh_dir + "/.ssh"
    } else if let Ok(ssh_dir) = env::var("USERPROFILE") {
        ssh_dir + "/.ssh"
    } else {
        "Unknown".to_string()
    }
}
// Implement other functions here

fn get_user_profile() -> String {
    if cfg!(windows) {
        match env::var("USERPROFILE") {
            Ok(val) => val,
            Err(_) => {
                print_error("Failed to fetch USERPROFILE environment variable.");
                std::process::exit(1);
            }
        }
    } else if cfg!(unix) {
        match env::var("HOME") {
            Ok(val) => val,
            Err(_) => {
                print_error("Failed to fetch HOME environment variable.");
                std::process::exit(1);
            }
        }
    } else {
        print_error("Unsupported operating system.");
        std::process::exit(1);
    }
}

// Linux main function
fn main_linux(_flag: &str) {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let flag = &args[1];

    match flag.as_str() {
        "-n" => {
            let file_name = &args[2];
            let passphrase_index = args.iter().position(|arg| arg == "-p");
            let passphrase = passphrase_index.and_then(|index| args.get(index + 1).map(|s| s.as_str()));
            generate_ssh_key_linux(file_name, passphrase);
        }
        "-rm" => {
            let file_name = &args[2];
            remove_ssh_key_linux(file_name);
        }
        "-l" => list_files_in_dir_linux(),
        "-c" => {
            if args.len() < 3 {
                print_error("Usage: -c <SSHKeyFileName> <User@IP>");
                return;
            }
            let remote_host = &args.last().unwrap();
            let ssh_key_name = if args.len() == 4 { args[2].as_str() } else { "" };
            if ssh_key_name.is_empty() {
                list_files_in_dir_linux();
                return;
            }
            let file_name = match remote_host.split('@').nth(0) {
                Some(name) => name,
                None => {
                    print_error("Invalid remote host format.");
                    return;
                }
            };
            copy_ssh_key_linux(remote_host, file_name);
        }
        _ => {
            print_error("Invalid command. See usage:");
            print_usage();
        }
    }
}

// Windows main function
fn main_windows(_flag: &str) {

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        
        print_usage();
        return;
    }

    let flag = &args[1];

    match flag.as_str() {
        "-n" => {
            let file_name = &args[2];
            let passphrase_index = args.iter().position(|arg| arg == "-p");
            let passphrase = passphrase_index.and_then(|index| args.get(index + 1).map(|s| s.as_str()));
            generate_ssh_key_windows(file_name, passphrase);
        }
        "-rm" => {
            let file_name = &args[2];
            remove_ssh_key_windows(file_name);
        }
        "-l" => list_files_in_dir_windows(),
        "-c" => {
            if args.len() < 3 {
                print_error("Usage: -c <SSHKeyFileName> <User@IP>");
                return;
            }
            let remote_host = &args.last().unwrap();
            let ssh_key_name = if args.len() == 4 { args[2].as_str() } else { "" };
            if ssh_key_name.is_empty() {
                list_files_in_dir_windows();
                return;
            }
            let file_name = match remote_host.split('@').nth(0) {
                Some(name) => name,
                None => {
                    print_error("Invalid remote host format.");
                    return;
                }
            };
            copy_ssh_key_windows(remote_host, file_name);
        }
        _ => {
            print_error("Invalid command. See usage:");
            
            print_usage();
        }
    }
}


fn generate_ssh_key_linux(file_name: &str, passphrase: Option<&str>) {
    let user_profile = get_user_profile();
    let private_key_path = format_ssh_path(&user_profile, file_name);
    let public_key_path = format!("{}.pub", private_key_path);

    if Path::new(&private_key_path).exists() || Path::new(&public_key_path).exists() {
        print_error(&format!(
            "SSH key with the name '{}' already exists. Please choose a different name.",
            file_name
        ));
        return;
    }

    let mut ssh_keygen_command = Command::new("ssh-keygen");
    ssh_keygen_command.arg("-t").arg("rsa").arg("-f").arg(&private_key_path);
    if let Some(pass) = passphrase {
        if !pass.is_empty() {
            ssh_keygen_command.arg("-N").arg(pass);
        }
    } else {
        ssh_keygen_command.arg("-N").arg("");
    }

    let output = ssh_keygen_command.output().expect("Failed to execute ssh-keygen command");

    if output.status.success() {
        print_success(&format!("SSH key '{}' generated successfully.", file_name));
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        print_error(&format!("Error generating SSH key: {}", error_message));
    }
}

fn remove_ssh_key_linux(file_name: &str) {
    let user_profile = get_user_profile();
    let private_key_path = format_ssh_path(&user_profile, file_name);
    let public_key_path = format!("{}.pub", private_key_path);

    if !Path::new(&private_key_path).exists() && !Path::new(&public_key_path).exists() {
        print_error(&format!(
            "SSH key with the name '{}' does not exist.",
            file_name
        ));
        return;
    }

    let output = Command::new("/bin/rm")
        .arg(&private_key_path)
        .arg(&public_key_path)
        .output()
        .expect("Failed to execute rm command");

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
fn list_files_in_dir_linux() {
    let user_profile = get_user_profile();
    let dir_path = format!("{}/.ssh", user_profile);
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

fn copy_ssh_key_linux(remote_host: &str, file_name: &str) {
    let user_profile = get_user_profile();
    let public_key_path = format!("{}/.ssh/{}.pub", user_profile, file_name);

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

fn generate_ssh_key_windows(file_name: &str, passphrase: Option<&str>) {
    let user_profile = get_user_profile();
    let private_key_path = format_ssh_path(&user_profile, file_name);
    let public_key_path = format!("{}.pub", private_key_path);

    if Path::new(&private_key_path).exists() || Path::new(&public_key_path).exists() {
        print_error(&format!(
            "SSH key with the name '{}' already exists. Please choose a different name.",
            file_name
        ));
        return;
    }

    let mut ssh_keygen_command = Command::new("ssh-keygen");
    ssh_keygen_command.arg("-t").arg("rsa").arg("-f").arg(&private_key_path);
    if let Some(pass) = passphrase {
        if !pass.is_empty() {
            ssh_keygen_command.arg("-N").arg(pass);
        }
    } else {
        ssh_keygen_command.arg("-N").arg("");
    }

    let output = ssh_keygen_command.output().expect("Failed to execute ssh-keygen command");

    if output.status.success() {
        print_success(&format!("SSH key '{}' generated successfully.", file_name));
    } else {
        let error_message = String::from_utf8_lossy(&output.stderr);
        print_error(&format!("Error generating SSH key: {}", error_message));
    }
}

fn remove_ssh_key_windows(file_name: &str) {
    let user_profile = get_user_profile();
    let private_key_path = format_ssh_path(&user_profile, file_name);
    let public_key_path = format!("{}.pub", private_key_path);

    if !Path::new(&private_key_path).exists() && !Path::new(&public_key_path).exists() {
        print_error(&format!(
            "SSH key with the name '{}' does not exist.",
            file_name
        ));
        return;
    }

    let output = Command::new("C:\\Windows\\System32\\cmd.exe")
    .arg("/C")
    .arg("del")
    .arg(&private_key_path)
    .arg(&public_key_path)
    .output()
    .expect("Failed to execute del command");

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

fn list_files_in_dir_windows() {
    let user_profile = get_user_profile();
    let dir_path = format!("{}/.ssh", user_profile);
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

fn copy_ssh_key_windows(remote_host: &str, file_name: &str) {
    let user_profile = get_user_profile();
    let public_key_path = format!("{}/.ssh/{}.pub", user_profile, file_name);

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




#[cfg(windows)]
fn format_ssh_path(user_profile: &str, file_name: &str) -> String {
    format!("{}\\.ssh\\{}", user_profile, file_name)
}

#[cfg(not(windows))]
fn format_ssh_path(user_profile: &str, file_name: &str) -> String {
    format!("{}/.ssh/{}", user_profile, file_name)
}

fn print_usage() {
    let header = ">_SSH Key Helper ";
    let footer = format!("OS: {}\nSSH Directory: {}", get_os_name(), get_ssh_dir());
    let cmd_descs = [
        ("-n", "<name>           | generate a new SSH key"),
        ("-p", "<passphrase>     | specify a passphrase for the SSH key (optional)"),
        ("-rm", "<name>           | remove an existing SSH key"),
        ("-l", "                 | list files in .ssh"),
        ("-c", "<file> <User@IP> | copy SSH key to a remote host"),
    ];

    

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




fn print_error(message: &str) {
    eprintln!("Error: {}", message);
}

fn print_success(message: &str) {
    println!("Success: {}", message);
}
