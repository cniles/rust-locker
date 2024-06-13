use std::{
    io::{BufRead, Error, Stdin, StdinLock, Stdout, Write},
    process::Command,
};

enum SttyArgs {
    EchoOn,
    EchoOff,
}

impl SttyArgs {
    fn value(&self) -> Vec<String> {
        match self {
            SttyArgs::EchoOn => vec!["echo".to_string()],
            SttyArgs::EchoOff => vec!["-echo".to_string()],
        }
    }
}

fn stty(args: SttyArgs) -> Result<(), Error> {
    Command::new("stty")
        .args(args.value())
        .spawn()
        .expect("success");
    Ok(())
}

pub struct Prompt {
    stdin: Stdin,
    stdout: Stdout,
}

impl Prompt {
    pub fn new() -> Self {
        Prompt {
            stdin: std::io::stdin(),
            stdout: std::io::stdout(),
        }
    }

    fn prompt_read(&mut self, mut guard: StdinLock<'_>, prompt: &str) -> Result<String, Error> {
        print!("{}", prompt);
        self.stdout.flush()?;
        let mut line = String::new();
        guard.read_line(&mut line)?;
        Ok(line.trim().to_string())
    }

    pub fn value(&mut self, prompt: &str) -> Result<String, Error> {
        let guard = self.stdin.lock();
        self.prompt_read(guard, prompt)
    }

    pub fn secret(&mut self, prompt: &str) -> Result<String, Error> {
        let guard = self.stdin.lock();
        stty(SttyArgs::EchoOff).expect("Echo off");
        let result = self.prompt_read(guard, prompt);
        println!();
        stty(SttyArgs::EchoOn).expect("Echo on");
        result
    }
}
