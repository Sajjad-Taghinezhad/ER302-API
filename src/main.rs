use rocket::serde::{json::Json, Serialize};
use serialport::SerialPort;
use std::io::{Read, Write};
use std::time::Duration;
use dotenv::dotenv; // For loading environment variables
use std::env; // To access environment variables

const PORTNAME: &str = "/dev/tty";
const BAUDRATE: u32 = 112500;
const HEADER: &[u8] = &[0xaa, 0xbb];
// Key A
const APPKEY: &[u8] = &[0x17, 0x05, 0x97, 0x27, 0x08, 0x59];
// Default Key
const DEFAULTKEY: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
// Key A all permission | Key B disabled
const KEYACCESS: &[u8] = &[0xFF, 0x07, 0x80, 0x69];

#[macro_use]
extern crate rocket;

#[derive(Serialize)]
struct ApiResponse {
    status: bool,
    data: String,
}

struct RFID {
    port: Box<dyn SerialPort>,
}

fn load_config() -> Result<(String, u32), Box<dyn std::error::Error>> {
    dotenv().ok(); // Load environment variables from `.env` file

    // Get the serial port and baudrate from the environment variables
    let portname = env::var("PORTNAME")?;
    let baudrate: u32 = env::var("BAUDRATE")?.parse()?;

    Ok((portname, baudrate))
}


impl RFID {
    // Constructor to create a new RFID instance
    fn new(port: Box<dyn SerialPort>) -> Self {
        RFID { port }
    }

    fn calculate_size(data: &[u8]) -> Vec<u8> {
        // Calculate the length and add 1
        let length = data.len() + 1;

        // Convert length to a 2-byte number in little-endian format
        let low_byte = (length & 0xFF) as u8; // Low byte
        let high_byte = ((length >> 8) & 0xFF) as u8; // High byte
        Vec::from([low_byte, high_byte])
    }

    // Function to calculate XOR over a slice of data
    fn calculate_xor(data: Vec<u8>) -> Vec<u8> {
        if data.len() < 4 {
            panic!("Data must have at least 4 elements to calculate XOR");
        }

        // Calculate XOR from index 3 to the end
        let xor = data[3..].iter().fold(0, |acc, &x| acc ^ x);

        // Append the XOR result to the data and return as a new vector
        let mut extended_data = Vec::from(data);
        extended_data.push(xor);
        extended_data
    }

    // Method to send the request through the serial port
    fn send_request(&mut self, input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Calculate XOR and prepare final data

        let mut data: Vec<u8> = input.to_vec();
        let size = Self::calculate_size(input);

        data.splice(0..0, size.iter().copied());
        data.splice(0..0, HEADER.iter().copied());

        let final_data = Self::calculate_xor(data);

        // Write data to the serial port
        match self.port.write(&final_data) {
            Ok(_) => {
                // println!("{} bytes written: {:X?}", bytes_written, final_data)
            }
            Err(e) => eprintln!("Failed to write to serial port: {}", e),
        }

        // Buffer to read data
        let mut buffer: Vec<u8> = vec![0; 1024]; // Allocate a large buffer initially
        match self.port.read(&mut buffer) {
            Ok(bytes_read) => {
                // Trim the buffer to the actual size of the data read
                buffer.truncate(bytes_read); // Keep only the bytes that were actually read
                                             // println!("{} bytes read: {:X?}", bytes_read, &buffer);
            }
            Err(e) => eprintln!("Failed to read from serial port: {}", e),
        }

        Ok(buffer) // Return the buffer with the actual size
    }

    // Beep
    fn beep(&mut self, time: u8) -> () {
        let mut beep: Vec<u8> = vec![0x00, 0x00, 0x06, 0x01];
        beep.extend_from_slice(&time.to_le_bytes());
        match self.send_request(beep.as_slice()){
            Ok(_) => (),
            Err(_) => println!("error to send data")
        }
    }

    // Request Mifare
    fn mifare_request(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mifare_request = &[0x00, 0x00, 0x01, 0x02, 0x52];
        self.send_request(mifare_request)?;
        Ok(())
    }

    // Anticollision
    fn anticollision(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let anticollision: &[u8] = &[0x00, 0x00, 0x02, 0x02];
        let cards = self.send_request(anticollision)?;
        Ok(cards)
    }

    // Select Card
    fn select_card(&mut self, cards: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let selected_card = &[
            0x00, 0x00, 0x03, 0x02, cards[9], cards[10], cards[11], cards[12],
        ];
        self.send_request(selected_card)?;
        Ok(())
    }

    // Authenticate on block 53
    fn authenticate(&mut self, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut auth: Vec<u8> = vec![0x00, 0x00, 0x07, 0x02, 0x60, 0x35];
        auth.extend_from_slice(key);
        self.send_request(auth.as_slice())?;
        Ok(())
    }

    // Read Balance from block 53
    fn read_balance_request(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        let read_balance: &[u8] = &[0x00, 0x00, 0x0B, 0x02, 0x35];
        let balance = self.send_request(read_balance)?;

        let num: u32 = u32::from_le_bytes([balance[9], balance[10], balance[11], balance[12]]);
        Ok(num)
    }

    // Init balance on block 53
    fn init_balance_request(&mut self, balance: u32) -> Result<(), Box<dyn std::error::Error>> {
        let mut init_balance: Vec<u8> = vec![0x00, 0x00, 0x0a, 0x02, 0x35];
        init_balance.extend_from_slice(&(balance.to_le_bytes()));
        self.send_request(init_balance.as_slice())?;
        Ok(())
    }

    // Increase balance on block 53
    fn increase_balance_request(&mut self, value: u32) -> Result<(), Box<dyn std::error::Error>> {
        let mut init_balance: Vec<u8> = vec![0x00, 0x00, 0x0D, 0x02, 0x35];
        init_balance.extend_from_slice(&(value.to_le_bytes()));
        self.send_request(init_balance.as_slice())?;
        Ok(())
    }

    // Decrease balance on block 53
    fn decrease_balance_request(&mut self, value: u32) -> Result<(), Box<dyn std::error::Error>> {
        let mut init_balance: Vec<u8> = vec![0x00, 0x00, 0x0c, 0x02, 0x35];
        init_balance.extend_from_slice(&(value.to_le_bytes()));
        self.send_request(init_balance.as_slice())?;
        Ok(())
    }

    // Init card with keys
    fn init_card_request(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut init_card: Vec<u8> = vec![0x00, 0x00, 0x09, 0x02, 0x37];
        init_card.extend_from_slice(APPKEY);
        init_card.extend_from_slice(KEYACCESS);
        init_card.extend_from_slice(DEFAULTKEY);
        self.send_request(init_card.as_slice())?;
        Ok(())
    }

    //########Functinalities##############################################################################################

    // Read id
    fn read_id(&mut self) -> Result<String, String> {
        match self.mifare_request().map_err(|e| e.to_string()) {
            Ok(_) => match self.anticollision().map_err(|e| e.to_string()) {
                Ok(cards) => {
                    if cards.len() > 13 {
                        self.beep(2);
                        Ok(cards[9..13]
                            .iter()
                            .map(|byte| format!("{:02X}", byte))
                            .collect::<Vec<String>>()
                            .join(""))
                    } else {
                        Err("Card not found".to_string())
                    }
                }

                Err(_) => Err("nothing".to_string()),
            },
            Err(_) => Err("Baghali".to_string()),
        }
    }

    // Read Balance
    fn read_balance(&mut self) -> Result<String, String> {
        match self.mifare_request().map_err(|e| e.to_string()) {
            Ok(_) => match self.anticollision().map_err(|e| e.to_string()) {
                Ok(cards) => {
                    if cards.len() > 13 {
                        self.select_card(&cards).map_err(|e| e.to_string())?;
                        match self.authenticate(APPKEY) {
                            Ok(_) => {
                        self.beep(2);

                                Ok((self.read_balance_request().map_err(|e| e.to_string())?)
                                    .to_string())
                            }
                            Err(_) => Err("Authentication failed".to_string()),
                        }
                    } else {
                        Err("Card not found".to_string())
                    }
                }

                Err(_) => Err("nothing".to_string()),
            },
            Err(_) => Err("Baghali".to_string()),
        }
    }

    // Init Balance
    fn init_balance(&mut self, value: u32) -> Result<String, String> {
        match self.mifare_request().map_err(|e| e.to_string()) {
            Ok(_) => match self.anticollision().map_err(|e| e.to_string()) {
                Ok(cards) => {
                    if cards.len() > 13 {
                        self.select_card(&cards).map_err(|e| e.to_string())?;
                        match self.authenticate(APPKEY) {
                            Ok(_) => {
                                self.init_balance_request(value).map_err(|e| e.to_string())?;
                                match self.read_balance() {
                                    Ok(data) => {
                        self.beep(2);

                                        Ok(data)
                                    }
                                    Err(_) => {
                                        Err("Balance has wrote to card but can't retrive balance".to_string())
                                    }

                                }
                            }
                            Err(_) => Err("Authentication failed".to_string()),
                        }
                    } else {
                        Err("Card not found".to_string())
                    }
                }

                Err(_) => Err("nothing".to_string()),
            },
            Err(_) => Err("Baghali".to_string()),
        }
    }

    fn increase(&mut self, value: u32) -> Result<String, String> {
        match self.mifare_request().map_err(|e| e.to_string()) {
            Ok(_) => match self.anticollision().map_err(|e| e.to_string()) {
                Ok(cards) => {
                    if cards.len() > 13 {
                        self.select_card(&cards).map_err(|e| e.to_string())?;
                        match self.authenticate(APPKEY) {
                            Ok(_) => {
                                self.increase_balance_request(value).map_err(|e| e.to_string())?;
                                match self.read_balance() {
                                    Ok(data) => {
                        self.beep(2);

                                        Ok(data)
                                    }
                                    Err(_) => {
                                        Err("Balance has wrote to card but can't retrive balance".to_string())
                                    }

                                }
                            }
                            Err(_) => Err("Authentication failed".to_string()),
                        }
                    } else {
                        Err("Card not found".to_string())
                    }
                }

                Err(_) => Err("nothing".to_string()),
            },
            Err(_) => Err("Baghali".to_string()),
        }
    }
    fn decrease(&mut self, value: u32) -> Result<String, String> {
        match self.mifare_request().map_err(|e| e.to_string()) {
            Ok(_) => match self.anticollision().map_err(|e| e.to_string()) {
                Ok(cards) => {
                    if cards.len() > 13 {
                        self.select_card(&cards).map_err(|e| e.to_string())?;
                        match self.authenticate(APPKEY) {
                            Ok(_) => {
                                self.decrease_balance_request(value).map_err(|e| e.to_string())?;
                                match self.read_balance() {
                                    Ok(data) => {
                        self.beep(2);

                                        Ok(data)
                                    }
                                    Err(_) => {
                                        Err("Balance has wrote to card but can't retrive balance".to_string())
                                    }

                                }
                            }
                            Err(_) => Err("Authentication failed".to_string()),
                        }
                    } else {
                        Err("Card not found".to_string())
                    }
                }

                Err(_) => Err("nothing".to_string()),
            },
            Err(_) => Err("Baghali".to_string()),
        }
    }
    fn init_card(&mut self) -> Result<String, String> {
        match self.mifare_request().map_err(|e| e.to_string()) {
            Ok(_) => match self.anticollision().map_err(|e| e.to_string()) {
                Ok(cards) => {
                    if cards.len() > 13 {
                        self.select_card(&cards).map_err(|e| e.to_string())?;
                        match self.authenticate(DEFAULTKEY) {
                            Ok(_) => {
                                match self.init_card_request() { 
                                    Ok(_) => {
                                        self.beep(2);
                                        
                                        Ok("Card configured successfully".to_string()) 
                                    },
                                    Err(data) => Err(format!("error: {} \n info : card was configured or there is a problem to config that",data.to_string(),))
                                }
                            }
                            Err(_) => Err("Authentication failed".to_string()),
                        }
                    } else {
                        Err("Card not found".to_string())
                    }
                }

                Err(_) => Err("nothing".to_string()),
            },
            Err(_) => Err("Baghali".to_string()),
        }
    }
}



#[launch]
fn rocket() -> _ {
    dotenv().ok(); // Load environment variables from a .env file
    let host = env::var("HOST").unwrap_or("0.0.0.0".to_string());
    let port: u16 = env::var("PORT")
    .unwrap_or("8000".to_string())
    .parse()
    .unwrap_or(8000);

    println!("Card Reader,Write API for Ehuoyan ER302 by https://sajx.net/ ⭐️");
    rocket::build()
        .configure(rocket::Config {
            address: host.parse().unwrap(),
            port,
            ..Default::default()
        })
        .mount(
            "/",
            routes![id, read_balance, set_balance, increase, decrease, initcard],
        )
}


#[get("/id")]
fn id() -> Json<ApiResponse> {
    let portname: String ;
    let baudrate: u32 ;
    
    match load_config() {
        Ok(conf) => (portname, baudrate) = conf , 
        Err(_) => (portname, baudrate) = (PORTNAME.to_string(), BAUDRATE)
    }
    match serialport::new(portname, baudrate)
        .timeout(Duration::from_secs(2))
        .open()
    {
        Ok(port) => {
            let mut rfid = RFID::new(port);

            match rfid.read_id() {
                Ok(data) => Json(ApiResponse {
                    status: true,
                    data: data,
                }),
                Err(data) => Json(ApiResponse {
                    status: false,
                    data: data,
                }),
            }
        }
        Err(_) => Json(ApiResponse {
            status: false,
            data: "Error in Connection".to_string(),
        }),
    }
}

#[get("/balance")]
fn read_balance() -> Json<ApiResponse> {
    let portname: String ;
    let baudrate: u32 ;
    
    match load_config() {
        Ok(conf) => (portname, baudrate) = conf , 
        Err(_) => (portname, baudrate) = (PORTNAME.to_string(), BAUDRATE)
    }
    match serialport::new(portname, baudrate)
        .timeout(Duration::from_secs(2))
        .open()
    {
        Ok(port) => {
            let mut rfid = RFID::new(port);

            match rfid.read_balance() {
                Ok(data) => Json(ApiResponse {
                    status: true,
                    data: data,
                }),
                Err(data) => Json(ApiResponse {
                    status: false,
                    data: data,
                }),
            }
        }
        Err(_) => Json(ApiResponse {
            status: false,
            data: "Error in Connection".to_string(),
        }),
    }
}


#[get("/balance/<value>")]
fn set_balance(value: u32) -> Json<ApiResponse> {
    let portname: String ;
    let baudrate: u32 ;
    
    match load_config() {
        Ok(conf) => (portname, baudrate) = conf , 
        Err(_) => (portname, baudrate) = (PORTNAME.to_string(), BAUDRATE)
    }
    match serialport::new(portname, baudrate)
        .timeout(Duration::from_secs(2))
        .open()
    {
        Ok(port) => {
            let mut rfid = RFID::new(port);

            match rfid.init_balance(value) {
                Ok(data) => Json(ApiResponse {
                    status: true,
                    data: data.to_string(),
                }),
                Err(data) => Json(ApiResponse {
                    status: false,
                    data: data,
                }),
            }
        }
        Err(_) => Json(ApiResponse {
            status: false,
            data: "Error in Connection".to_string(),
        }),
    }
}

#[get("/increase/<value>")]
fn increase(value: u32) -> Json<ApiResponse> {
    let portname: String ;
    let baudrate: u32 ;
    
    match load_config() {
        Ok(conf) => (portname, baudrate) = conf , 
        Err(_) => (portname, baudrate) = (PORTNAME.to_string(), BAUDRATE)
    }
    match serialport::new(portname, baudrate)
        .timeout(Duration::from_secs(2))
        .open()
    {
        Ok(port) => {
            let mut rfid = RFID::new(port);

            match rfid.increase(value) {
                Ok(data) => Json(ApiResponse {
                    status: true,
                    data: data.to_string(),
                }),
                Err(data) => Json(ApiResponse {
                    status: false,
                    data: data,
                }),
            }
        }
        Err(_) => Json(ApiResponse {
            status: false,
            data: "Error in Connection".to_string(),
        }),
    }
}

#[get("/decrease/<value>")]
fn decrease(value: u32) -> Json<ApiResponse> {
    let portname: String ;
    let baudrate: u32 ;
    
    match load_config() {
        Ok(conf) => (portname, baudrate) = conf , 
        Err(_) => (portname, baudrate) = (PORTNAME.to_string(), BAUDRATE)
    }
    match serialport::new(portname, baudrate)
        .timeout(Duration::from_secs(2))
        .open()
    {
        Ok(port) => {
            let mut rfid = RFID::new(port);

            match rfid.decrease(value) {
                Ok(data) => Json(ApiResponse {
                    status: true,
                    data: data.to_string(),
                }),
                Err(data) => Json(ApiResponse {
                    status: false,
                    data: data,
                }),
            }
        }
        Err(_) => Json(ApiResponse {
            status: false,
            data: "Error in Connection".to_string(),
        }),
    }
}

#[get("/initcard")]
fn initcard() -> Json<ApiResponse> {
    let portname: String ;
    let baudrate: u32 ;
    
    match load_config() {
        Ok(conf) => (portname, baudrate) = conf , 
        Err(_) => (portname, baudrate) = (PORTNAME.to_string(), BAUDRATE)
    }
    match serialport::new(portname, baudrate)
        .timeout(Duration::from_secs(2))
        .open()
    {
        Ok(port) => {
            let mut rfid = RFID::new(port);

            match rfid.init_card() {
                Ok(data) => Json(ApiResponse {
                    status: true,
                    data: data.to_string(),
                }),
                Err(data) => Json(ApiResponse {
                    status: false,
                    data: data,
                }),
            }
        }
        Err(_) => Json(ApiResponse {
            status: false,
            data: "Error in Connection".to_string(),
        }),
    }
}
