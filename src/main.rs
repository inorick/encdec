use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::exit;

use orion::{aead, kdf};
use std::mem::size_of_val;
use orion::hash::{Digest, digest};
use orion::kdf::SecretKey;

const BUF_MAX_SIZE: usize = 1024 * 1024;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        print_usage(&args[0]);
        exit(0);
    }

    // open file
    let filename = &args[1];
    let input_path = Path::new(filename);
    let display = input_path.display();
    let mut input_file = match File::open(&input_path) {
        Ok(file) => file,
        Err(_why) => {
            println!("couldn't open file {}", display);
            exit(-1);
        }
    };

    // ask user for password
    let user_input = rpassword::read_password_from_tty(Some("please enter password: ")).unwrap();
    let user_password = kdf::Password::from_slice(user_input.as_bytes()).unwrap();
    let salt: kdf::Salt = kdf::Salt::from_slice(&[0]).unwrap();
    println!("deriving key ...");
    let mut chunk_key = kdf::derive_key(&user_password, &salt, 10000, 32).unwrap();

    // read file
    let mut content_buf = [0; BUF_MAX_SIZE];
    let mut is_last_chunk = false;
    let mut chunk_nr = 1;
    while !is_last_chunk {
        let bytes_read = match input_file.read(&mut content_buf) {
            Ok(n) => n,
            Err(_why) => {
                println!("couldn't read file {}", display);
                exit(-1);
            }
        };

        // process data
        let chunk_data;
        let output_path_str;
        if input_path.extension().unwrap() == "enc" {
            // decrypt data
            println!("decrypting file ...");
            chunk_data = match aead::open(&chunk_key, &content_buf) {
                Ok(data) => data,
                Err(why) => {
                    println!("could not decrypt file: {}", why);
                    exit(-1);
                }
            };

            output_path_str = String::from(input_path.file_stem().unwrap().to_str().unwrap());
        } else {
            // encrypt data
            println!("encrypting file ...");
            chunk_data = match aead::seal(&chunk_key, &content_buf) {
                Ok(n) => n,
                Err(why) => {
                    println!("could not encrypt file: {}", why);
                    exit(-1);
                }
            };

            output_path_str = String::from(format!("{}.enc", input_path.to_str().unwrap()).as_str());
        }

        // write output file
        let output_path = Path::new(&output_path_str);
        println!("writing output file: {:?}", output_path);
        let mut output_file = File::create(output_path).unwrap();
        let _write_result = output_file.write(&chunk_data);

        let mut last_chunk_hash: Digest;
        if bytes_read == BUF_MAX_SIZE {
            let mut buf_end = content_buf[(BUF_MAX_SIZE - 16)..].to_vec();
            last_chunk_hash = digest(&buf_end).unwrap();
            println!("last_chunk_hash.get_length()={}", last_chunk_hash.get_length())
//            chunk_key = last_chunk_hash;
        } else {
            is_last_chunk = true;
        }

        println!("processed chunk nr {}", chunk_nr);
        chunk_nr = chunk_nr + 1;
    }
}

fn print_usage(program_name: &String) {
    println!("usage: {} <plaintext-file>", program_name);
}