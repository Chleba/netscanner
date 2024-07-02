use std::{env, error::Error, io, process};

fn write_csv() -> Result<(), Box<dyn Error>> {
    let mut csv_wtr = csv::Writer::from_writer(io::stdout());
    csv_wtr.write_record(["maslo", "maslo1", "maslo2", "maslo3"])?;
    csv_wtr.write_record(["1", "12", "maslo12", "maslo13"])?;
    csv_wtr.write_record(["maslo", "maslo1", "maslo2", "maslo3"])?;

    csv_wtr.flush()?;

    Ok(())
}

fn main() {
    println!("{:?}", env::vars_os());

    match env::var_os("SUDO_USER") {
        Some(val) => println!("SUDO_USER: {val:?}"),
        None => println!("SUDO_USER was not found")
    }

    match env::var_os("HOME") {
        Some(val) => println!("HOME: {val:?}"),
        None => println!("HOME was not found")
    }

    if let Err(err) = write_csv() {
        println!("{}", err);
        process::exit(1);
    }
}

