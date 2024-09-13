use awdb_rs::DB;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = DB::open("db/IP_city_single_WGS84_awdb.awdb")?;

    let ip = "66.240.205.34".parse()?;
    let resp = db.lookup(ip)?;

    println!("{:#?}", resp);

    Ok(())
}
