# Project

This is rust-locker.  Its a simple command line tool for securely storing and retrieving secrets.

## Directory

./src/main.rs - the main program logic and command line integration
./src/vault.rs - an abstraction around locking and unlocking a file to retrieve its secrets
./src/prompt.rs - wraps the terminal to allow secret text entry

## Priorities

Security, correctness, integrity and preservation are the priorities.
